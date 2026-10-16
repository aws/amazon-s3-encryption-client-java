// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import org.junit.jupiter.api.Test;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.encryption.s3.S3EncryptionClientException;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the file-based part-upload path in {@link UploadObjectObserver}.
 *
 * <p>In the high-level multipart put path each part is a finished ciphertext file on disk, so a
 * part body must support being read more than once -- the AWS SDK re-subscribes to the request
 * body when it retries a part.
 *
 * <p>No AWS resources: {@link S3AsyncClient} is mocked, and its {@code uploadPart} stub drives the
 * request body by subscribing to it twice.
 */
class UploadObjectObserverTest {

    /**
     * Reads an {@link AsyncRequestBody} fully into a byte array, blocking until done.
     * A body that forbids a second subscription throws synchronously on the second call.
     */
    private static byte[] drain(AsyncRequestBody body) throws Exception {
        final CompletableFuture<byte[]> done = new CompletableFuture<>();
        body.subscribe(new Subscriber<ByteBuffer>() {
            private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

            @Override
            public void onSubscribe(Subscription s) {
                s.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(ByteBuffer bb) {
                byte[] chunk = new byte[bb.remaining()];
                bb.get(chunk);
                buffer.write(chunk, 0, chunk.length);
            }

            @Override
            public void onError(Throwable t) {
                done.completeExceptionally(t);
            }

            @Override
            public void onComplete() {
                done.complete(buffer.toByteArray());
            }
        });
        return done.get(15, TimeUnit.SECONDS);
    }

    /**
     * A file-based part body supports being read more than once: the mocked {@code uploadPart}
     * subscribes twice, as the SDK does when it retries a part, and both reads succeed and return
     * byte-identical content.
     */
    @Test
    void onPartCreate_partBodyAllowsSdkRetryResubscription() throws Exception {
        // A static ciphertext part on disk, as the multipart path produces.
        byte[] ciphertext = new byte[128 * 1024];
        new Random(42).nextBytes(ciphertext);
        File part = File.createTempFile("s3ec-part-", ".bin");
        part.deleteOnExit();
        Files.write(part.toPath(), ciphertext);

        AtomicInteger subscribeCount = new AtomicInteger(0);
        List<byte[]> reads = new CopyOnWriteArrayList<>();

        S3AsyncClient s3Async = mock(S3AsyncClient.class);
        when(s3Async.uploadPart(any(UploadPartRequest.class), any(AsyncRequestBody.class)))
                .thenAnswer(invocation -> {
                    AsyncRequestBody body = invocation.getArgument(1);
                    // Attempt #1.
                    subscribeCount.incrementAndGet();
                    reads.add(drain(body));
                    // Attempt #2: the SDK re-subscribes to the same body to retry.
                    subscribeCount.incrementAndGet();
                    reads.add(drain(body));
                    return CompletableFuture.completedFuture(
                            UploadPartResponse.builder().eTag("etag-part-1").build());
                });

        ExecutorService es = Executors.newSingleThreadExecutor();
        try {
            // onPartCreate doesn't use s3EncryptionClient, so null is safe here.
            UploadObjectObserver observer = new UploadObjectObserver().init(
                    PutObjectRequest.builder().bucket("test-bucket").key("test-key").build(),
                    s3Async,
                    null,
                    es);

            observer.onPartCreate(new PartCreationEvent(part, 1, true, null));

            Map<Integer, UploadPartResponse> result =
                    observer.futures().get(0).get(30, TimeUnit.SECONDS);

            // The part upload completes after the second subscription.
            assertEquals(1, result.size());
            assertEquals("etag-part-1", result.get(1).eTag());

            // Both subscriptions saw identical bytes -- re-reading a file is safe.
            assertEquals(2, subscribeCount.get(), "SDK retry should re-subscribe to the part body");
            assertEquals(2, reads.size());
            assertArrayEquals(ciphertext, reads.get(0), "first read must equal the ciphertext file");
            assertArrayEquals(reads.get(0), reads.get(1),
                    "SDK retry must observe byte-identical part content");
        } finally {
            es.shutdownNow();
        }
    }

    /**
     * After a part uploads, its temporary ciphertext file is deleted and the file-delete observer
     * is notified once.
     */
    @Test
    void onPartCreate_deletesPartFileAndNotifiesObserverAfterUpload() throws Exception {
        byte[] ciphertext = new byte[32 * 1024];
        new Random(99).nextBytes(ciphertext);
        File part = File.createTempFile("s3ec-part-cleanup-", ".bin");
        part.deleteOnExit();
        Files.write(part.toPath(), ciphertext);

        S3AsyncClient s3Async = mock(S3AsyncClient.class);
        when(s3Async.uploadPart(any(UploadPartRequest.class), any(AsyncRequestBody.class)))
                .thenReturn(CompletableFuture.completedFuture(
                        UploadPartResponse.builder().eTag("etag-part-1").build()));

        AtomicInteger deleteNotifications = new AtomicInteger(0);
        OnFileDelete fileDeleteObserver = event -> deleteNotifications.incrementAndGet();

        ExecutorService es = Executors.newSingleThreadExecutor();
        try {
            UploadObjectObserver observer = new UploadObjectObserver().init(
                    PutObjectRequest.builder().bucket("test-bucket").key("test-key").build(),
                    s3Async,
                    null,
                    es);

            observer.onPartCreate(new PartCreationEvent(part, 1, true, fileDeleteObserver));
            observer.futures().get(0).get(30, TimeUnit.SECONDS);

            assertFalse(part.exists(), "the part file must be deleted after the upload completes");
            assertEquals(1, deleteNotifications.get(),
                    "the file-delete observer must be notified once after the part is deleted");
        } finally {
            es.shutdownNow();
        }
    }

    /**
     * A failure from the part upload is surfaced as an {@link S3EncryptionClientException} that
     * carries the original cause, rather than the SDK's wrapping {@link CompletionException}.
     */
    @Test
    void onPartCreate_unwrapsUploadFailureIntoS3EncryptionClientException() throws Exception {
        byte[] ciphertext = new byte[16 * 1024];
        new Random(5).nextBytes(ciphertext);
        File part = File.createTempFile("s3ec-part-fail-", ".bin");
        part.deleteOnExit();
        Files.write(part.toPath(), ciphertext);

        RuntimeException cause = new RuntimeException("simulated transport failure");
        CompletableFuture<UploadPartResponse> failed = new CompletableFuture<>();
        failed.completeExceptionally(cause);

        S3AsyncClient s3Async = mock(S3AsyncClient.class);
        when(s3Async.uploadPart(any(UploadPartRequest.class), any(AsyncRequestBody.class)))
                .thenReturn(failed);

        ExecutorService es = Executors.newSingleThreadExecutor();
        try {
            UploadObjectObserver observer = new UploadObjectObserver().init(
                    PutObjectRequest.builder().bucket("test-bucket").key("test-key").build(),
                    s3Async,
                    null,
                    es);

            observer.onPartCreate(new PartCreationEvent(part, 1, true, null));

            ExecutionException ex = assertThrows(ExecutionException.class,
                    () -> observer.futures().get(0).get(30, TimeUnit.SECONDS));
            assertTrue(ex.getCause() instanceof S3EncryptionClientException,
                    "the upload failure must surface as an S3EncryptionClientException");
            assertEquals(cause, ex.getCause().getCause(),
                    "the original cause must be preserved, not the wrapping CompletionException");
        } finally {
            es.shutdownNow();
        }
    }
}
