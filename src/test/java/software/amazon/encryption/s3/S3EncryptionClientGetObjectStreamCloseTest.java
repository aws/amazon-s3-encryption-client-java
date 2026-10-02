// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.async.SdkPublisher;
import software.amazon.awssdk.core.checksums.RequestChecksumCalculation;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.http.SdkHttpFullResponse;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.async.AsyncExecuteRequest;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.http.async.SdkAsyncHttpResponseHandler;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * Verifies that {@link S3EncryptionClient#getObject} releases the response stream it opens on the
 * wrapped async client, so the underlying HTTP connection is returned to the pool.
 * <p>
 * The wrapped async client is a real {@link S3AsyncClient} backed by an in-memory transport, so the
 * full encrypt / decrypt path runs. The object is larger than what the blocking input stream buffers,
 * and delayed authentication is enabled so plaintext is streamed rather than buffered in full; a
 * transformer that stops reading early therefore leaves the response body unconsumed, and the only
 * thing that releases it is the client closing (cancelling) the stream.
 */
public class S3EncryptionClientGetObjectStreamCloseTest {

    private static final String BUCKET = "test-bucket";
    private static final String KEY = "test-key";
    private static final int OBJECT_SIZE = 8 * 1024 * 1024;
    private static final int CHUNK_SIZE = 64 * 1024;

    private InMemoryTransport transport;
    private S3EncryptionClient client;
    private byte[] plaintext;

    @BeforeEach
    public void setUp() {
        transport = new InMemoryTransport();
        StaticCredentialsProvider creds = StaticCredentialsProvider.create(AwsBasicCredentials.create("akid", "skid"));
        S3AsyncClient wrappedAsyncClient = S3AsyncClient.builder()
                .region(Region.US_WEST_2)
                .credentialsProvider(creds)
                .requestChecksumCalculation(RequestChecksumCalculation.WHEN_REQUIRED)
                .httpClient(transport)
                .build();
        S3Client wrappedClient = S3Client.builder()
                .region(Region.US_WEST_2)
                .credentialsProvider(creds)
                .build();

        byte[] keyBytes = new byte[32];
        new SecureRandom().nextBytes(keyBytes);
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        client = S3EncryptionClient.builderV4()
                .wrappedClient(wrappedClient)
                .wrappedAsyncClient(wrappedAsyncClient)
                .aesKey(aesKey)
                .enableDelayedAuthenticationMode(true)
                .build();

        plaintext = new byte[OBJECT_SIZE];
        new SecureRandom().nextBytes(plaintext);
        client.putObject(PutObjectRequest.builder().bucket(BUCKET).key(KEY).build(), RequestBody.fromBytes(plaintext));
    }

    @AfterEach
    public void tearDown() {
        client.close();
        transport.shutdown();
    }

    @Test
    public void bufferingTransformerThatStopsEarlyReleasesResponseStream() {
        // needsConnectionLeftOpen() is false, so the client owns the stream and must close it.
        int firstByte = client.getObject(getRequest(), (response, inputStream) -> inputStream.read());

        assertEquals(plaintext[0] & 0xFF, firstByte);
        assertTrue(transport.lastBody.awaitCancelled(), "response stream was not released after getObject returned");
    }

    @Test
    public void transformerThatThrowsReleasesResponseStream() {
        assertThrows(S3EncryptionClientException.class, () -> client.getObject(getRequest(), (response, inputStream) -> {
            inputStream.read();
            throw new IllegalStateException("transform failed");
        }));

        assertTrue(transport.lastBody.awaitCancelled(), "response stream was not released after transform threw");
    }

    @Test
    public void streamingTransformerLeavesResponseStreamOpenForCaller() throws Exception {
        try (ResponseInputStream<GetObjectResponse> stream = client.getObject(getRequest(), ResponseTransformer.toInputStream())) {
            assertFalse(transport.lastBody.cancelled.get(), "caller-owned stream was closed by getObject");
            assertEquals(plaintext[0] & 0xFF, stream.read());
        }

        assertTrue(transport.lastBody.awaitCancelled(), "response stream was not released after the caller closed it");
    }

    @Test
    public void fullyConsumedResponseStillDecryptsCorrectly() {
        byte[] result = client.getObjectAsBytes(getRequest()).asByteArray();

        assertEquals(OBJECT_SIZE, result.length);
        assertTrue(java.util.Arrays.equals(plaintext, result));
    }

    private static GetObjectRequest getRequest() {
        return GetObjectRequest.builder().bucket(BUCKET).key(KEY).build();
    }

    /** Stores a single object on PUT and serves it on GET, recording whether the GET body was cancelled. */
    private static final class InMemoryTransport implements SdkAsyncHttpClient {
        private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "in-memory-transport");
            t.setDaemon(true);
            return t;
        });
        private final Map<String, String> storedMetadata = new HashMap<>();
        private byte[] storedBody;
        volatile RecordingBodyPublisher lastBody;

        @Override
        public CompletableFuture<Void> execute(AsyncExecuteRequest request) {
            return request.request().method() == SdkHttpMethod.PUT ? put(request) : get(request);
        }

        private CompletableFuture<Void> put(AsyncExecuteRequest request) {
            CompletableFuture<Void> done = new CompletableFuture<>();
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            request.requestContentPublisher().subscribe(new Subscriber<ByteBuffer>() {
                @Override
                public void onSubscribe(Subscription subscription) {
                    subscription.request(Long.MAX_VALUE);
                }

                @Override
                public void onNext(ByteBuffer byteBuffer) {
                    byte[] bytes = new byte[byteBuffer.remaining()];
                    byteBuffer.get(bytes);
                    body.write(bytes, 0, bytes.length);
                }

                @Override
                public void onError(Throwable t) {
                    request.responseHandler().onError(t);
                    done.completeExceptionally(t);
                }

                @Override
                public void onComplete() {
                    storedBody = body.toByteArray();
                    request.request().headers().forEach((name, values) -> {
                        if (name.toLowerCase().startsWith("x-amz-meta-")) {
                            storedMetadata.put(name, values.get(0));
                        }
                    });
                    SdkAsyncHttpResponseHandler handler = request.responseHandler();
                    handler.onHeaders(SdkHttpFullResponse.builder().statusCode(200).putHeader("ETag", "\"etag\"").build());
                    handler.onStream(new RecordingBodyPublisher(new byte[0], CHUNK_SIZE, executor));
                    done.complete(null);
                }
            });
            return done;
        }

        private CompletableFuture<Void> get(AsyncExecuteRequest request) {
            SdkHttpFullResponse.Builder response = SdkHttpFullResponse.builder()
                    .statusCode(200)
                    .putHeader("ETag", "\"etag\"")
                    .putHeader("Content-Length", String.valueOf(storedBody.length));
            storedMetadata.forEach(response::putHeader);
            lastBody = new RecordingBodyPublisher(storedBody, CHUNK_SIZE, executor);

            SdkAsyncHttpResponseHandler handler = request.responseHandler();
            handler.onHeaders(response.build());
            handler.onStream(lastBody);
            return CompletableFuture.completedFuture(null);
        }

        void shutdown() {
            executor.shutdownNow();
        }

        @Override
        public String clientName() {
            return "in-memory-transport";
        }

        @Override
        public void close() {
        }
    }

    /**
     * Emits the body in chunks only as they are requested, like a real HTTP client applying
     * backpressure, and records whether the subscriber cancelled.
     */
    private static final class RecordingBodyPublisher implements SdkPublisher<ByteBuffer> {
        private final byte[] body;
        private final int chunkSize;
        private final ExecutorService executor;
        final AtomicBoolean cancelled = new AtomicBoolean(false);
        private final CompletableFuture<Void> cancelledFuture = new CompletableFuture<>();

        private RecordingBodyPublisher(byte[] body, int chunkSize, ExecutorService executor) {
            this.body = body;
            this.chunkSize = chunkSize;
            this.executor = executor;
        }

        boolean awaitCancelled() {
            try {
                cancelledFuture.get(5, TimeUnit.SECONDS);
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
            subscriber.onSubscribe(new Subscription() {
                private long demand;
                private int position;
                private boolean delivering;
                private boolean terminated;

                @Override
                public void request(long n) {
                    synchronized (this) {
                        if (terminated) {
                            return;
                        }
                        demand = demand + n < 0 ? Long.MAX_VALUE : demand + n;
                        if (delivering) {
                            return;
                        }
                        delivering = true;
                    }
                    executor.execute(this::deliver);
                }

                private void deliver() {
                    while (true) {
                        ByteBuffer chunk;
                        boolean complete = false;
                        synchronized (this) {
                            if (terminated || demand == 0) {
                                delivering = false;
                                return;
                            }
                            if (position >= body.length) {
                                terminated = true;
                                complete = true;
                                chunk = null;
                            } else {
                                int length = Math.min(chunkSize, body.length - position);
                                chunk = ByteBuffer.wrap(body, position, length).slice();
                                position += length;
                                demand--;
                            }
                        }
                        if (complete) {
                            subscriber.onComplete();
                            return;
                        }
                        subscriber.onNext(chunk);
                    }
                }

                @Override
                public void cancel() {
                    synchronized (this) {
                        terminated = true;
                    }
                    cancelled.set(true);
                    cancelledFuture.complete(null);
                }
            });
        }
    }
}
