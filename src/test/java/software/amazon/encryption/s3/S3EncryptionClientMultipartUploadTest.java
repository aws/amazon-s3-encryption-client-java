// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.SdkPartType;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.utils.BoundedInputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class S3EncryptionClientMultipartUploadTest {
    private static Provider PROVIDER;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        PROVIDER = Security.getProvider("BC");
    }

    @Test
    public void multipartPutObjectAsync() throws IOException {
        final String objectKey = appendTestSuffix("multipart-put-object-async");

        final long fileSizeLimit = 1024 * 1024 * 100;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
        final InputStream objectStreamForResult = new BoundedInputStream(fileSizeLimit);

        S3AsyncClient v3Client = S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableMultipartPutObject(true)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(PROVIDER)
                .build();

        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        ExecutorService singleThreadExecutor = Executors.newSingleThreadExecutor();
        
        CompletableFuture<PutObjectResponse> futurePut = v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
                .key(objectKey), AsyncRequestBody.fromInputStream(inputStream, fileSizeLimit, singleThreadExecutor));
        futurePut.join();
        singleThreadExecutor.shutdown();

        // Asserts
        CompletableFuture<ResponseInputStream<GetObjectResponse>> getFuture = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(S3EncryptionClient.withAdditionalConfiguration(encryptionContext))
                .key(objectKey), AsyncResponseTransformer.toBlockingInputStream());
        ResponseInputStream<GetObjectResponse> output = getFuture.join();

        assertTrue(IOUtils.contentEquals(objectStreamForResult, output));

        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void multipartPutObjectAsyncLargeObjectFails() {
        final String objectKey = appendTestSuffix("multipart-put-object-async-large-object-fails");

        // Tight bound on the max GCM limit
        final long fileSizeLimit = ((1L << 39) - 256 / 8) + 1;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);

        S3AsyncClient v3Client = S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableMultipartPutObject(true)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(PROVIDER)
                .build();

        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        ExecutorService singleThreadExecutor = Executors.newSingleThreadExecutor();

        assertThrows(S3EncryptionClientException.class, () -> v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
                .key(objectKey), AsyncRequestBody.fromInputStream(inputStream, fileSizeLimit, singleThreadExecutor)));

        v3Client.close();
        singleThreadExecutor.shutdown();
    }

    @Test
    public void multipartPutObject() throws IOException {
        final String objectKey = appendTestSuffix("multipart-put-object");

        final long fileSizeLimit = 1024 * 1024 * 100;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
        final InputStream objectStreamForResult = new BoundedInputStream(fileSizeLimit);

        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableMultipartPutObject(true)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(PROVIDER)
                .build();

        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
                .key(objectKey), RequestBody.fromInputStream(inputStream, fileSizeLimit));

        // Asserts
        ResponseInputStream<GetObjectResponse> output = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(S3EncryptionClient.withAdditionalConfiguration(encryptionContext))
                .key(objectKey));

        assertTrue(IOUtils.contentEquals(objectStreamForResult, output));

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }

    /*
     This test ensures that an object larger than the max safe GCM limit
     cannot be uploaded using the low-level multipart upload API.
     It is currently disabled as it alone takes 10x the duration of the
     entire rest of the test suite. In the future, it would be best to
     have a "long" test suite containing this test and any other tests
     which take more than 5-10 minutes to complete.
     */
//    @Test
//    public void multipartUploadV3OutputStreamLargeObjectFails() throws IOException {
//        final String objectKey = appendTestSuffix("multipart-upload-v3-output-stream-fails");
//
//        // Overall "file" is ~68GB, split into 10MB parts
//        // Tight bound on the max GCM limit
//        final long fileSizeLimit = ((1L << 39) - 256 / 8) + 1;
//        final int PART_SIZE = 10 * 1024 * 1024;
//        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
//
//        // V3 Client
//        S3Client v3Client = S3EncryptionClient.builder()
//                .kmsKeyId(KMS_KEY_ID)
//                .enableDelayedAuthenticationMode(true)
//                .cryptoProvider(PROVIDER)
//                .build();
//
//        // Create Multipart upload request to S3
//        CreateMultipartUploadResponse initiateResult = v3Client.createMultipartUpload(builder ->
//                builder.bucket(BUCKET).key(objectKey));
//
//        List<CompletedPart> partETags = new ArrayList<>();
//
//        int bytesRead, bytesSent = 0;
//        // 10MB parts
//        byte[] partData = new byte[PART_SIZE];
//        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//        int partsSent = 1;
//
//        while ((bytesRead = inputStream.read(partData, 0, partData.length)) != -1) {
//            outputStream.write(partData, 0, bytesRead);
//            if (bytesSent < PART_SIZE) {
//                bytesSent += bytesRead;
//                continue;
//            }
//
//            UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
//                    .bucket(BUCKET)
//                    .key(objectKey)
//                    .uploadId(initiateResult.uploadId())
//                    .partNumber(partsSent)
//                    .build();
//
//            final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
//            UploadPartResponse uploadPartResult = v3Client.uploadPart(uploadPartRequest,
//                    RequestBody.fromInputStream(partInputStream, partInputStream.available()));
//            partETags.add(CompletedPart.builder()
//                    .partNumber(partsSent)
//                    .eTag(uploadPartResult.eTag())
//                    .build());
//            outputStream.reset();
//            bytesSent = 0;
//            partsSent++;
//        }
//        inputStream.close();
//
//        // Last Part
//        UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
//                .bucket(BUCKET)
//                .key(objectKey)
//                .uploadId(initiateResult.uploadId())
//                .partNumber(partsSent)
//                .sdkPartType(SdkPartType.LAST)
//                .build();
//
//        final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
//        UploadPartResponse uploadPartResult = v3Client.uploadPart(uploadPartRequest,
//                RequestBody.fromInputStream(partInputStream, partInputStream.available()));
//        partETags.add(CompletedPart.builder()
//                .partNumber(partsSent)
//                .eTag(uploadPartResult.eTag())
//                .build());
//
//        // Complete the multipart upload.
//        v3Client.completeMultipartUpload(builder -> builder
//                .bucket(BUCKET)
//                .key(objectKey)
//                .uploadId(initiateResult.uploadId())
//                .multipartUpload(partBuilder -> partBuilder.parts(partETags)));
//
//        // Asserts
//        InputStream resultStream = v3Client.getObjectAsBytes(builder -> builder
//                .bucket(BUCKET)
//                .key(objectKey)).asInputStream();
//
//        assertTrue(IOUtils.contentEquals(new BoundedInputStream(fileSizeLimit), resultStream));
//        resultStream.close();
//
//        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
//        v3Client.close();
//    }

    @Test
    public void multipartPutObjectLargeObjectFails() {
        final String objectKey = appendTestSuffix("multipart-put-object-large-fails");

        // Tight bound on the max GCM limit
        final long fileSizeLimit = ((1L << 39) - 256 / 8) + 1;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);

        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableMultipartPutObject(true)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(PROVIDER)
                .build();

        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        assertThrows(S3EncryptionClientException.class, () -> v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
                .key(objectKey), RequestBody.fromInputStream(inputStream, fileSizeLimit)));

        v3Client.close();
    }


    @Test
    public void multipartUploadV3OutputStream() throws IOException {
        final String objectKey = appendTestSuffix("multipart-upload-v3-output-stream");

        // Overall "file" is 100MB, split into 10MB parts
        final long fileSizeLimit = 1024 * 1024 * 100;
        final int PART_SIZE = 10 * 1024 * 1024;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(PROVIDER)
                .build();

        // Create Multipart upload request to S3
        CreateMultipartUploadResponse initiateResult = v3Client.createMultipartUpload(builder ->
                builder.bucket(BUCKET).key(objectKey));

        List<CompletedPart> partETags = new ArrayList<>();

        int bytesRead, bytesSent = 0;
        // 10MB parts
        byte[] partData = new byte[PART_SIZE];
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int partsSent = 1;

        while ((bytesRead = inputStream.read(partData, 0, partData.length)) != -1) {
            outputStream.write(partData, 0, bytesRead);
            if (bytesSent < PART_SIZE) {
                bytesSent += bytesRead;
                continue;
            }

            UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                    .bucket(BUCKET)
                    .key(objectKey)
                    .uploadId(initiateResult.uploadId())
                    .partNumber(partsSent)
                    .build();

            final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
            UploadPartResponse uploadPartResult = v3Client.uploadPart(uploadPartRequest,
                    RequestBody.fromInputStream(partInputStream, partInputStream.available()));
            partETags.add(CompletedPart.builder()
                    .partNumber(partsSent)
                    .eTag(uploadPartResult.eTag())
                    .build());
            outputStream.reset();
            bytesSent = 0;
            partsSent++;
        }
        inputStream.close();

        // Last Part
        UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .partNumber(partsSent)
                .sdkPartType(SdkPartType.LAST)
                .build();

        final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
        UploadPartResponse uploadPartResult = v3Client.uploadPart(uploadPartRequest,
                RequestBody.fromInputStream(partInputStream, partInputStream.available()));
        partETags.add(CompletedPart.builder()
                .partNumber(partsSent)
                .eTag(uploadPartResult.eTag())
                .build());

        // Complete the multipart upload.
        v3Client.completeMultipartUpload(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .multipartUpload(partBuilder -> partBuilder.parts(partETags)));

        // Asserts
        InputStream resultStream = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)).asInputStream();

        assertTrue(IOUtils.contentEquals(new BoundedInputStream(fileSizeLimit), resultStream));
        resultStream.close();

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }

    @Test
    public void multipartUploadV3OutputStreamPartSize() throws IOException {
        final String objectKey = appendTestSuffix("multipart-upload-v3-output-stream-part-size");

        // Overall "file" is 30MB, split into 10MB parts
        final long fileSizeLimit = 1024 * 1024 * 30;
        final int PART_SIZE = 10 * 1024 * 1024;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(PROVIDER)
                .build();

        // Create Multipart upload request to S3
        CreateMultipartUploadResponse initiateResult = v3Client.createMultipartUpload(builder ->
                builder.bucket(BUCKET).key(objectKey));

        List<CompletedPart> partETags = new ArrayList<>();

        int bytesRead, bytesSent = 0;
        // 10MB parts
        byte[] partData = new byte[PART_SIZE];
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int partsSent = 1;

        while ((bytesRead = inputStream.read(partData, 0, partData.length)) != -1) {
            outputStream.write(partData, 0, bytesRead);
            if (bytesSent < PART_SIZE) {
                bytesSent += bytesRead;
                continue;
            }

            final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
            UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                    .bucket(BUCKET)
                    .key(objectKey)
                    .uploadId(initiateResult.uploadId())
                    .partNumber(partsSent)
                    .contentLength((long) partInputStream.available())
                    .build();

            UploadPartResponse uploadPartResult = v3Client.uploadPart(uploadPartRequest,
                    RequestBody.fromInputStream(partInputStream, partInputStream.available()));
            partETags.add(CompletedPart.builder()
                    .partNumber(partsSent)
                    .eTag(uploadPartResult.eTag())
                    .build());
            outputStream.reset();
            bytesSent = 0;
            partsSent++;
        }

        final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());

        // Last Part
        UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .partNumber(partsSent)
                .contentLength((long) partInputStream.available())
                .sdkPartType(SdkPartType.LAST)
                .build();

        UploadPartResponse uploadPartResult = v3Client.uploadPart(uploadPartRequest,
                RequestBody.fromInputStream(partInputStream, partInputStream.available()));
        partETags.add(CompletedPart.builder()
                .partNumber(partsSent)
                .eTag(uploadPartResult.eTag())
                .build());

        // Complete the multipart upload.
        v3Client.completeMultipartUpload(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .multipartUpload(partBuilder -> partBuilder.parts(partETags)));

        // Asserts
        ResponseBytes<GetObjectResponse> result = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));

        String inputAsString = IoUtils.toUtf8String(new BoundedInputStream(fileSizeLimit));
        String outputAsString = IoUtils.toUtf8String(result.asInputStream());
        assertEquals(inputAsString, outputAsString);

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }

    @Test
    public void multipartUploadV3OutputStreamPartSizeMismatch() throws IOException {
        final String objectKey = appendTestSuffix("multipart-upload-v3-output-stream-part-size-mismatch");

        // Overall "file" is 30MB, split into 10MB parts
        final long fileSizeLimit = 1024 * 1024 * 30;
        final int PART_SIZE = 10 * 1024 * 1024;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(PROVIDER)
                .build();

        // Create Multipart upload request to S3
        CreateMultipartUploadResponse initiateResult = v3Client.createMultipartUpload(builder ->
                builder.bucket(BUCKET).key(objectKey));

        int bytesRead, bytesSent = 0;
        // 10MB parts
        byte[] partData = new byte[PART_SIZE];
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int partsSent = 1;

        while ((bytesRead = inputStream.read(partData, 0, partData.length)) != -1) {
            outputStream.write(partData, 0, bytesRead);
            if (bytesSent < PART_SIZE) {
                bytesSent += bytesRead;
                continue;
            }

            final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
            UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                    .bucket(BUCKET)
                    .key(objectKey)
                    .uploadId(initiateResult.uploadId())
                    .partNumber(partsSent)
                    .contentLength((long) partInputStream.available() + 1) // mismatch
                    .build();

            assertThrows(S3EncryptionClientException.class, () -> v3Client.uploadPart(uploadPartRequest,
                    RequestBody.fromInputStream(partInputStream, partInputStream.available())));
        }

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }

}
