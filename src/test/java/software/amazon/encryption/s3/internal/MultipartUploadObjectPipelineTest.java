// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import org.junit.jupiter.api.Test;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterialsRequest;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link MultipartUploadObjectPipeline#uploadPart}, the low-level multipart encrypt
 * path. No AWS resources: the {@link S3AsyncClient} and the {@link CryptographicMaterialsManager}
 * are mocked, and real local AES-GCM materials drive a genuine cipher stream.
 */
class MultipartUploadObjectPipelineTest {

    private static final String BUCKET = "test-bucket";
    private static final String KEY = "test-key";
    private static final String UPLOAD_ID = "test-upload-id";
    // A part size that is a multiple of the AES block size (16), as required for a non-final part.
    private static final int PART_SIZE = 64;

    /** Discards whatever the live-cipher body produces; it only needs to drive one subscription. */
    private static Subscriber<ByteBuffer> discardingSubscriber() {
        return new Subscriber<ByteBuffer>() {
            @Override
            public void onSubscribe(Subscription s) {
                s.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(ByteBuffer byteBuffer) {
                // discard ciphertext
            }

            @Override
            public void onError(Throwable t) {
                // the second subscription is rejected synchronously at subscribe() time, before any
                // onError; nothing to do here for this test
            }

            @Override
            public void onComplete() {
            }
        };
    }

    /**
     * Builds a pipeline over a mocked async S3 client whose CMM yields real, local AES-256-GCM
     * encryption materials, then seeds an in-progress multipart upload so {@code uploadPart} has a
     * live cipher to stream through.
     */
    private static MultipartUploadObjectPipeline pipelineWithSeededUpload(S3AsyncClient s3Async) {
        CryptographicMaterialsManager cmm = mock(CryptographicMaterialsManager.class);
        when(cmm.getEncryptionMaterials(any(EncryptionMaterialsRequest.class)))
                .thenAnswer(invocation -> EncryptionMaterials.builder()
                        .s3Request(invocation.<EncryptionMaterialsRequest>getArgument(0).s3Request())
                        .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                        .plaintextDataKey(new byte[32]) // 256-bit data key; value is irrelevant to the guard
                        .encryptedDataKeys(Collections.singletonList(EncryptedDataKey.builder()
                                .keyProviderId("test-provider")
                                .keyProviderInfo("test-key")
                                .encryptedDataKey(new byte[32])
                                .build()))
                        .build());

        // createMultipartUpload only needs an upload id back to key the client-side materials.
        when(s3Async.createMultipartUpload(any(CreateMultipartUploadRequest.class)))
                .thenReturn(CompletableFuture.completedFuture(
                        CreateMultipartUploadResponse.builder().uploadId(UPLOAD_ID).build()));

        MultipartUploadObjectPipeline pipeline = MultipartUploadObjectPipeline.builder()
                .s3AsyncClient(s3Async)
                .cryptoMaterialsManager(cmm)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .secureRandom(new SecureRandom())
                .instructionFileConfig(InstructionFileConfig.builder()
                        .disableInstructionFile(true)
                        .build())
                .build();

        pipeline.createMultipartUpload(
                CreateMultipartUploadRequest.builder().bucket(BUCKET).key(KEY).build());
        return pipeline;
    }

    /**
     * The request body that {@code uploadPart} hands to the SDK for a multipart part wraps the live
     * AES-GCM cipher stream in {@link NoRetriesAsyncRequestBody}, so an SDK retry that re-subscribes
     * to the same body is rejected with an {@link S3EncryptionClientException} rather than feeding
     * the cipher a second time (which would corrupt the ciphertext). This is the crypto-pipeline
     * guarantee for the multipart wrap site.
     */
    @Test
    void uploadPart_rejectsResubscriptionToLiveCipherBody() {
        AtomicInteger acceptedSubscriptions = new AtomicInteger(0);
        AtomicReference<Throwable> resubscribeError = new AtomicReference<>();

        S3AsyncClient s3Async = mock(S3AsyncClient.class);
        when(s3Async.uploadPart(any(UploadPartRequest.class), any(AsyncRequestBody.class)))
                .thenAnswer(invocation -> {
                    AsyncRequestBody partBody = invocation.getArgument(1);
                    // First subscription: the SDK's normal single read of the part body.
                    partBody.subscribe(discardingSubscriber());
                    acceptedSubscriptions.incrementAndGet();
                    // Second subscription: an SDK retry re-reading the SAME live-cipher body.
                    try {
                        partBody.subscribe(discardingSubscriber());
                        acceptedSubscriptions.incrementAndGet();
                    } catch (Throwable t) {
                        resubscribeError.set(t);
                    }
                    return CompletableFuture.completedFuture(
                            UploadPartResponse.builder().eTag("etag-part-1").build());
                });

        MultipartUploadObjectPipeline pipeline = pipelineWithSeededUpload(s3Async);

        UploadPartResponse response = pipeline.uploadPart(
                UploadPartRequest.builder()
                        .bucket(BUCKET).key(KEY).uploadId(UPLOAD_ID).partNumber(1)
                        .contentLength((long) PART_SIZE)
                        .build(),
                RequestBody.fromBytes(new byte[PART_SIZE]));

        // The part itself still uploads on the first (only) accepted subscription.
        assertEquals("etag-part-1", response.eTag());

        // Exactly one subscription was accepted; the retry's re-subscription was turned away.
        assertEquals(1, acceptedSubscriptions.get(),
                "only the first subscription to the live-cipher part body may be accepted");

        Throwable error = resubscribeError.get();
        assertNotNull(error,
                "re-subscription to the multipart live-cipher body must be rejected, not silently re-read");
        assertInstanceOf(S3EncryptionClientException.class, error);
        assertTrue(error.getMessage().contains("Re-subscription is not supported"),
                "unexpected rejection message: " + error.getMessage());
    }
}
