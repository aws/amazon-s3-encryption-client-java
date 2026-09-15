// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import org.junitpioneer.jupiter.RetryingTest;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.S3_REGION;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

/**
 * Verifies that the S3EC preserves the per-request {@link AwsRequestOverrideConfiguration} set by
 * the caller. The client adds its own API name to every request's override configuration; these
 * tests ensure that doing so does not discard a caller-supplied override configuration (such as a
 * custom header, credentials provider, or signer override).
 * <p>
 * Each test attaches a custom header via the request-level override configuration and inspects the
 * request that actually reaches the wrapped client using an {@link ExecutionInterceptor}.
 */
public class S3EncryptionClientRequestOverrideConfigurationTest {

    private static final String CUSTOM_HEADER_NAME = "x-amz-meta-s3ec-override-repro";
    private static final String CUSTOM_HEADER_VALUE = "custom-value";

    private static SecretKey AES_KEY;

    private static SecretKey aesKey() throws NoSuchAlgorithmException {
        if (AES_KEY == null) {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            AES_KEY = keyGen.generateKey();
        }
        return AES_KEY;
    }

    /**
     * Captures the outgoing HTTP request for a given method so the test can assert on the
     * headers that actually reach the wire.
     */
    private static class CapturingInterceptor implements ExecutionInterceptor {
        private final SdkHttpMethod methodToCapture;
        private final AtomicReference<SdkHttpRequest> capturedRequest = new AtomicReference<>();

        CapturingInterceptor(SdkHttpMethod methodToCapture) {
            this.methodToCapture = methodToCapture;
        }

        @Override
        public void beforeTransmission(Context.BeforeTransmission context, ExecutionAttributes executionAttributes) {
            SdkHttpRequest request = context.httpRequest();
            if (request.method() == methodToCapture) {
                capturedRequest.set(request);
            }
        }

        SdkHttpRequest captured() {
            return capturedRequest.get();
        }
    }

    @RetryingTest(3)
    public void putObjectPreservesRequestOverrideConfiguration() throws NoSuchAlgorithmException {
        final String objectKey = appendTestSuffix("override-config-repro-put");

        CapturingInterceptor interceptor = new CapturingInterceptor(SdkHttpMethod.PUT);
        S3AsyncClient wrappedAsyncClient = S3AsyncClient.builder()
                .region(Region.of(S3_REGION.toString()))
                .overrideConfiguration(ClientOverrideConfiguration.builder()
                        .addExecutionInterceptor(interceptor)
                        .build())
                .build();

        S3AsyncClient s3Client = S3AsyncEncryptionClient.builderV4()
                .wrappedClient(wrappedAsyncClient)
                .aesKey(aesKey())
                .build();

        final String input = "PutObjectOverrideConfig";
        final AwsRequestOverrideConfiguration overrideConfig = AwsRequestOverrideConfiguration.builder()
                .putHeader(CUSTOM_HEADER_NAME, CUSTOM_HEADER_VALUE)
                .build();

        try {
            s3Client.putObject(builder -> builder
                            .bucket(BUCKET)
                            .key(objectKey)
                            .overrideConfiguration(overrideConfig)
                            .build(),
                    AsyncRequestBody.fromString(input)).join();

            SdkHttpRequest sentRequest = interceptor.captured();
            assertNotNull(sentRequest, "No PutObject request was captured by the interceptor");

            // The S3EC API name must still be present (existing behavior must be preserved).
            Optional<String> userAgent = sentRequest.firstMatchingHeader("User-Agent");
            assertTrue(userAgent.isPresent() && userAgent.get().contains("AmazonS3Encrypt"),
                    "Expected the S3EC API name to be present in the User-Agent header");

            // The caller-provided override configuration (custom header) must NOT be dropped.
            Optional<String> customHeader = sentRequest.firstMatchingHeader(CUSTOM_HEADER_NAME);
            assertTrue(customHeader.isPresent(),
                    "Caller-provided request override configuration (custom header) was dropped on PutObject");
            assertEquals(CUSTOM_HEADER_VALUE, customHeader.get());
        } finally {
            deleteObject(BUCKET, objectKey, s3Client);
            s3Client.close();
            wrappedAsyncClient.close();
        }
    }

    @RetryingTest(3)
    public void getObjectPreservesRequestOverrideConfiguration() throws NoSuchAlgorithmException {
        final String objectKey = appendTestSuffix("override-config-repro-get");

        CapturingInterceptor interceptor = new CapturingInterceptor(SdkHttpMethod.GET);
        S3AsyncClient wrappedAsyncClient = S3AsyncClient.builder()
                .region(Region.of(S3_REGION.toString()))
                .overrideConfiguration(ClientOverrideConfiguration.builder()
                        .addExecutionInterceptor(interceptor)
                        .build())
                .build();

        S3AsyncClient s3Client = S3AsyncEncryptionClient.builderV4()
                .wrappedClient(wrappedAsyncClient)
                .aesKey(aesKey())
                .build();

        final String input = "GetObjectOverrideConfig";
        final AwsRequestOverrideConfiguration overrideConfig = AwsRequestOverrideConfiguration.builder()
                .putHeader(CUSTOM_HEADER_NAME, CUSTOM_HEADER_VALUE)
                .build();

        try {
            // Put without an override so the capturing interceptor only sees the GET below.
            s3Client.putObject(builder -> builder
                            .bucket(BUCKET)
                            .key(objectKey)
                            .build(),
                    AsyncRequestBody.fromString(input)).join();

            ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObject(builder -> builder
                            .bucket(BUCKET)
                            .key(objectKey)
                            .overrideConfiguration(overrideConfig)
                            .build(),
                    AsyncResponseTransformer.toBytes()).join();
            assertEquals(input, objectResponse.asUtf8String());

            SdkHttpRequest sentRequest = interceptor.captured();
            assertNotNull(sentRequest, "No GetObject request was captured by the interceptor");

            Optional<String> customHeader = sentRequest.firstMatchingHeader(CUSTOM_HEADER_NAME);
            assertTrue(customHeader.isPresent(),
                    "Caller-provided request override configuration (custom header) was dropped on GetObject");
            assertEquals(CUSTOM_HEADER_VALUE, customHeader.get());
        } finally {
            deleteObject(BUCKET, objectKey, s3Client);
            s3Client.close();
            wrappedAsyncClient.close();
        }
    }
}
