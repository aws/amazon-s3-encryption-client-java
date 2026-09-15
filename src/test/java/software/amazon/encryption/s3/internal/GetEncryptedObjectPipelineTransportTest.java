// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntFunction;

import org.junit.jupiter.api.Test;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.async.SdkPublisher;
import software.amazon.awssdk.http.SdkHttpFullResponse;
import software.amazon.awssdk.http.async.AsyncExecuteRequest;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.http.async.SdkAsyncHttpResponseHandler;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.utils.CompletableFutureUtils;
import software.amazon.encryption.s3.CommitmentPolicy;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DecryptMaterialsRequest;
import software.amazon.encryption.s3.materials.DecryptionMaterials;

/**
 * Drives the decryption-setup failure path through a real {@link S3AsyncClient} backed by a fake
 * transport, so the SDK's own response-handler chain decides when {@code onResponse} and {@code onStream}
 * are invoked. The fake plays only the role of netty: signal headers, then signal the body publisher
 * (which {@code ResponseHandler} does regardless of what the handler did with the headers), and
 * optionally signal an error.
 * <p>
 * Stubbing {@code S3AsyncClient} and calling the transformer callbacks by hand would assume the very
 * thing under test - that the SDK still delivers the ciphertext publisher after setup has failed.
 */
public class GetEncryptedObjectPipelineTransportTest {

    private static final String BUCKET = "test-bucket";
    private static final String KEY = "test-key";

    /** Well-formed V3 committing-suite envelope, so metadata decode succeeds. */
    private static final Map<String, String> VALID_V3_METADATA = validV3Metadata();

    /** No S3EC metadata, so decode falls through to the (disabled) instruction file and fails. */
    private static final Map<String, String> NO_S3EC_METADATA = Collections.emptyMap();

    /**
     * The CMM yields no materials, so decryption cannot start. The publisher must still be drained and
     * the failure must still reach the caller.
     */
    @Test
    public void testSdkStillDeliversStreamAfterSetupFailureAndPublisherIsDrained() {
        CryptographicMaterialsManager cmm = mock(CryptographicMaterialsManager.class);
        when(cmm.decryptMaterials(any(DecryptMaterialsRequest.class))).thenReturn(null);

        RecordingPublisher body = new RecordingPublisher(3);
        FakeTransport transport = new FakeTransport(attempt -> new Attempt(VALID_V3_METADATA, body, null));

        try (S3AsyncClient s3AsyncClient = fakeBackedClient(transport)) {
            CompletableFuture<ResponseBytes<GetObjectResponse>> future = pipeline(s3AsyncClient, cmm, false)
                    .getObject(GetObjectRequest.builder().bucket(BUCKET).key(KEY).build(),
                            AsyncResponseTransformer.toBytes());

            assertFailureMessageContains(future, "Decryption materials cannot be null");
            assertDrained(body, 3);
            assertEquals(1, transport.executeCount.get(), "expected a single HTTP attempt");
        }
    }

    /**
     * Metadata decode fails rather than the CMM. Same requirement: drain, and surface the cause.
     */
    @Test
    public void testMetadataDecodeFailureDrainsAndSurfacesCause() {
        CryptographicMaterialsManager cmm = mock(CryptographicMaterialsManager.class);

        RecordingPublisher body = new RecordingPublisher(2);
        FakeTransport transport = new FakeTransport(attempt -> new Attempt(NO_S3EC_METADATA, body, null));

        try (S3AsyncClient s3AsyncClient = fakeBackedClient(transport)) {
            CompletableFuture<ResponseBytes<GetObjectResponse>> future = pipeline(s3AsyncClient, cmm, false)
                    .getObject(GetObjectRequest.builder().bucket(BUCKET).key(KEY).build(),
                            AsyncResponseTransformer.toBytes());

            assertFailureMessageContains(future, "Exception encountered while fetching Instruction File");
            assertDrained(body, 2);
        }
    }

    /**
     * Exercises the {@code prepare()} reset through the SDK's real retry loop rather than by calling
     * {@code prepare()} by hand.
     * <p>
     * Attempt 1 resolves materials and then fails with a retryable transport error. Attempt 2 returns
     * undecodable metadata, so {@code onResponse} fails. Without the reset, attempt 2's {@code onStream}
     * would see attempt 1's materials and set up decryption over attempt 2's body - decrypting one
     * response's bytes with another response's IV and message ID - instead of draining it.
     * <p>
     * The caller's future fails either way (the SDK reports the decode failure from {@code onHeaders}), so
     * the observable signal is whether attempt 2's body gets drained.
     */
    @Test
    public void testRetryDoesNotDecryptWithPreviousAttemptMaterials() {
        CryptographicMaterialsManager cmm = mock(CryptographicMaterialsManager.class);
        when(cmm.decryptMaterials(any(DecryptMaterialsRequest.class))).thenReturn(
                DecryptionMaterials.builder()
                        .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                        .plaintextDataKey(new byte[32])
                        .ciphertextLength(48L)
                        .build());

        RecordingPublisher secondAttemptBody = new RecordingPublisher(2);
        FakeTransport transport = new FakeTransport(attempt -> attempt == 1
                // Attempt 1: metadata decodes and materials resolve, then the transport fails retryably.
                ? new Attempt(VALID_V3_METADATA, null, new IOException("connection reset"))
                // Attempt 2: undecodable metadata, so onResponse fails and onStream must drain.
                : new Attempt(NO_S3EC_METADATA, secondAttemptBody, null));

        try (S3AsyncClient s3AsyncClient = fakeBackedClient(transport)) {
            CompletableFuture<ResponseBytes<GetObjectResponse>> future = pipeline(s3AsyncClient, cmm, true)
                    .getObject(GetObjectRequest.builder().bucket(BUCKET).key(KEY).build(),
                            AsyncResponseTransformer.toBytes());

            assertThrows(CompletionException.class, future::join);
            assertTrue(transport.executeCount.get() >= 2,
                    "expected the SDK to retry; attempts=" + transport.executeCount.get());
            assertDrained(secondAttemptBody, 2);
        }
    }

    /**
     * The success counterpart to the drain tests: when metadata decodes and materials resolve, onStream
     * must wire the ciphertext through the decrypting publisher to the wrapped transformer rather than
     * take the drain path. Guards against a future change making onStream drain unconditionally.
     * <p>
     * The only property asserted is that the wrapped transformer receives a plaintext publisher, because
     * that is all this fixture can establish. The synthetic envelope cannot survive key-commitment
     * validation (that would mean deriving a matching commitment via HKDF, i.e. forging a real object),
     * so decryption never consumes the body here; real end-to-end decrypts are covered by the
     * S3EncryptionClient integration tests.
     * <p>
     * The wait is on the callback rather than on the caller's future: the drain path completes neither the
     * wrapped transformer's stream nor its future, so joining the future would hang on regression instead
     * of failing.
     */
    @Test
    public void testSuccessfulSetupWiresPlaintextStreamAndDoesNotDrain() throws Exception {
        CryptographicMaterialsManager cmm = mock(CryptographicMaterialsManager.class);
        when(cmm.decryptMaterials(any(DecryptMaterialsRequest.class))).thenReturn(
                DecryptionMaterials.builder()
                        .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                        .plaintextDataKey(new byte[32])
                        .ciphertextLength(48L)
                        .build());

        RecordingPublisher body = new RecordingPublisher(2);
        FakeTransport transport = new FakeTransport(attempt -> new Attempt(VALID_V3_METADATA, body, null));

        CountDownLatch onStreamReceived = new CountDownLatch(1);
        RecordingTransformer transformer = new RecordingTransformer(onStreamReceived);

        try (S3AsyncClient s3AsyncClient = fakeBackedClient(transport)) {
            // enableDelayedAuthentication=true so a CipherPublisher (not BufferedCipherPublisher) is used.
            CompletableFuture<String> future = pipeline(s3AsyncClient, cmm, true)
                    .getObject(GetObjectRequest.builder().bucket(BUCKET).key(KEY).build(), transformer);

            assertTrue(onStreamReceived.await(3, TimeUnit.SECONDS),
                    "onStream must forward the plaintext publisher to the wrapped transformer on success; "
                            + "the drain path never calls the wrapped onStream");

            // Outcome is irrelevant to this test - the synthetic envelope fails commitment validation.
            future.exceptionally(t -> null).join();
        }
    }

    private static void assertDrained(RecordingPublisher body, int expectedElements) {
        assertTrue(body.subscribed.get(),
                "ciphertext publisher was never subscribed - onStream abandoned the body instead of draining it");
        assertEquals(expectedElements, body.delivered.get(),
                "the whole body must be consumed so the response terminates normally");
    }

    private static void assertFailureMessageContains(CompletableFuture<?> future, String expected) {
        CompletionException thrown = assertThrows(CompletionException.class, future::join,
                "the setup failure must still be surfaced to the caller");
        assertNotNull(thrown.getCause());
        assertTrue(thrown.getCause().getMessage().contains(expected),
                "unexpected failure: " + thrown.getCause());
    }

    private static Map<String, String> validV3Metadata() {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-c", "115");
        metadata.put("x-amz-3", "ZW5jcnlwdGVkLWtleS1kYXRh");
        metadata.put("x-amz-m", "{\"test\":\"material-desc\"}");
        metadata.put("x-amz-w", "02");
        metadata.put("x-amz-d", "a2V5LWNvbW1pdG1lbnQtZGF0YQ==");
        metadata.put("x-amz-i", "dGVzdC1tZXNzYWdlLWlk");
        return Collections.unmodifiableMap(metadata);
    }

    private static S3AsyncClient fakeBackedClient(SdkAsyncHttpClient transport) {
        return S3AsyncClient.builder()
                .region(Region.US_WEST_2)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("akid", "skid")))
                .httpClient(transport)
                .build();
    }

    private static GetEncryptedObjectPipeline pipeline(S3AsyncClient s3AsyncClient,
                                                       CryptographicMaterialsManager cmm,
                                                       boolean enableDelayedAuthentication) {
        return GetEncryptedObjectPipeline.builder()
                .s3AsyncClient(s3AsyncClient)
                .cryptoMaterialsManager(cmm)
                .enableLegacyUnauthenticatedModes(false)
                .enableDelayedAuthentication(enableDelayedAuthentication)
                .bufferSize(1024)
                .instructionFileConfig(InstructionFileConfig.builder()
                        .disableInstructionFile(true)
                        .build())
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .build();
    }

    /**
     * Caller transformer for the success test. Counts down the supplied latch when onStream is invoked -
     * the signal the test waits on - and drains whatever plaintext publisher it receives so the exchange
     * can proceed. It still completes its own future on stream completion/error, but the test waits on the
     * latch rather than the future, since the drain-regression path completes neither.
     */
    private static final class RecordingTransformer implements AsyncResponseTransformer<GetObjectResponse, String> {
        private final CountDownLatch onStreamReceived;
        private CompletableFuture<String> future;

        private RecordingTransformer(CountDownLatch onStreamReceived) {
            this.onStreamReceived = onStreamReceived;
        }

        @Override
        public CompletableFuture<String> prepare() {
            future = new CompletableFuture<>();
            return future;
        }

        @Override
        public void onResponse(GetObjectResponse response) {
        }

        @Override
        public void onStream(SdkPublisher<ByteBuffer> plaintextPublisher) {
            onStreamReceived.countDown();
            plaintextPublisher.subscribe(new Subscriber<ByteBuffer>() {
                @Override
                public void onSubscribe(Subscription subscription) {
                    subscription.request(Long.MAX_VALUE);
                }

                @Override
                public void onNext(ByteBuffer byteBuffer) {
                    // discard plaintext
                }

                @Override
                public void onError(Throwable t) {
                    future.completeExceptionally(t);
                }

                @Override
                public void onComplete() {
                    future.complete("ok");
                }
            });
        }

        @Override
        public void exceptionOccurred(Throwable error) {
            if (future != null) {
                future.completeExceptionally(error);
            }
        }
    }

    /** What the fake transport does for a single attempt. */
    private static final class Attempt {
        private final Map<String, String> metadata;
        private final SdkPublisher<ByteBuffer> body;
        private final Throwable error;

        private Attempt(Map<String, String> metadata, SdkPublisher<ByteBuffer> body, Throwable error) {
            this.metadata = metadata;
            this.body = body;
            this.error = error;
        }
    }

    /** Stands in for netty: headers, then body publisher, then optional error. */
    private static final class FakeTransport implements SdkAsyncHttpClient {
        private final IntFunction<Attempt> attempts;
        final AtomicInteger executeCount = new AtomicInteger(0);

        private FakeTransport(IntFunction<Attempt> attempts) {
            this.attempts = attempts;
        }

        @Override
        public CompletableFuture<Void> execute(AsyncExecuteRequest request) {
            Attempt attempt = attempts.apply(executeCount.incrementAndGet());
            SdkAsyncHttpResponseHandler handler = request.responseHandler();

            SdkHttpFullResponse.Builder response = SdkHttpFullResponse.builder()
                    .statusCode(200)
                    .putHeader("Content-Length", "48");
            // S3 surfaces user metadata as x-amz-meta-* headers.
            attempt.metadata.forEach((k, v) -> response.putHeader("x-amz-meta-" + k, v));
            handler.onHeaders(response.build());

            if (attempt.body != null) {
                handler.onStream(attempt.body);
            }
            if (attempt.error != null) {
                handler.onError(attempt.error);
                return CompletableFutureUtils.failedFuture(attempt.error);
            }
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public String clientName() {
            return "fake-transport";
        }

        @Override
        public void close() {
        }
    }

    /** Records whether it was subscribed and how many elements were delivered. */
    private static final class RecordingPublisher implements SdkPublisher<ByteBuffer> {
        private final int elementCount;
        final AtomicBoolean subscribed = new AtomicBoolean(false);
        final AtomicInteger delivered = new AtomicInteger(0);

        private RecordingPublisher(int elementCount) {
            this.elementCount = elementCount;
        }

        @Override
        public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
            subscribed.set(true);
            subscriber.onSubscribe(new Subscription() {
                private int remaining = elementCount;
                private boolean terminated;

                @Override
                public void request(long n) {
                    if (terminated) {
                        return;
                    }
                    long budget = n;
                    while (remaining > 0 && budget > 0) {
                        remaining--;
                        budget--;
                        delivered.incrementAndGet();
                        subscriber.onNext(ByteBuffer.allocate(16));
                    }
                    if (remaining == 0) {
                        terminated = true;
                        subscriber.onComplete();
                    }
                }

                @Override
                public void cancel() {
                    terminated = true;
                }
            });
        }
    }
}
