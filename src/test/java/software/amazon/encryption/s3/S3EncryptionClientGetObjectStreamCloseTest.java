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

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.SdkPublisher;
import software.amazon.awssdk.core.checksums.RequestChecksumCalculation;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.http.SdkHttpFullResponse;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.async.AsyncExecuteRequest;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * Verifies that {@link S3EncryptionClient#getObject} closes the response stream unless the caller
 * owns it, so the underlying HTTP connection is released.
 * <p>
 * The wrapped async client runs over an in-memory transport whose response body is delivered in
 * chunks on demand, like a real connection. The object is larger than the blocking input stream
 * buffers and delayed authentication streams plaintext, so a transformer that stops reading early
 * leaves the body unconsumed; only closing the stream cancels it.
 */
public class S3EncryptionClientGetObjectStreamCloseTest {

    private static final GetObjectRequest GET_REQUEST = GetObjectRequest.builder().bucket("bucket").key("key").build();

    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final InMemoryTransport transport = new InMemoryTransport(executor);
    private S3EncryptionClient client;
    private byte[] plaintext;

    @BeforeEach
    public void setUp() {
        StaticCredentialsProvider creds = StaticCredentialsProvider.create(AwsBasicCredentials.create("akid", "skid"));
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        client = S3EncryptionClient.builderV4()
                .wrappedClient(S3Client.builder().region(Region.US_WEST_2).credentialsProvider(creds).build())
                .wrappedAsyncClient(S3AsyncClient.builder()
                        .region(Region.US_WEST_2)
                        .credentialsProvider(creds)
                        // Keeps the PUT body unencoded so the transport can store it as-is.
                        .requestChecksumCalculation(RequestChecksumCalculation.WHEN_REQUIRED)
                        .httpClient(transport)
                        .build())
                .aesKey(new SecretKeySpec(key, "AES"))
                .enableDelayedAuthenticationMode(true)
                .build();

        plaintext = new byte[8 * 1024 * 1024];
        new SecureRandom().nextBytes(plaintext);
        client.putObject(PutObjectRequest.builder().bucket("bucket").key("key").build(), RequestBody.fromBytes(plaintext));
    }

    @AfterEach
    public void tearDown() {
        client.close();
        executor.shutdownNow();
    }

    @Test
    public void transformerThatStopsEarlyReleasesResponseStream() {
        int firstByte = client.getObject(GET_REQUEST, (response, inputStream) -> inputStream.read());

        assertEquals(plaintext[0] & 0xFF, firstByte);
        assertTrue(transport.awaitBodyCancelled(), "response stream was not released after getObject returned");
    }

    @Test
    public void transformerThatThrowsReleasesResponseStream() {
        assertThrows(S3EncryptionClientException.class, () -> client.getObject(GET_REQUEST, (response, inputStream) -> {
            inputStream.read();
            throw new IllegalStateException("transform failed");
        }));

        assertTrue(transport.awaitBodyCancelled(), "response stream was not released after transform threw");
    }

    @Test
    public void streamingTransformerLeavesResponseStreamOpenForCaller() throws Exception {
        try (ResponseInputStream<GetObjectResponse> stream = client.getObject(GET_REQUEST, ResponseTransformer.toInputStream())) {
            assertEquals(plaintext[0] & 0xFF, stream.read());
            assertFalse(transport.bodyCancelled.isDone(), "caller-owned stream was closed by getObject");
        }

        assertTrue(transport.awaitBodyCancelled(), "response stream was not released after the caller closed it");
    }

    /** Stores the object on PUT and serves it on GET, recording whether the GET body was cancelled. */
    private static final class InMemoryTransport implements SdkAsyncHttpClient {
        private final ExecutorService executor;
        private final Map<String, String> metadata = new HashMap<>();
        private byte[] body;
        private volatile CompletableFuture<Void> bodyCancelled = new CompletableFuture<>();

        InMemoryTransport(ExecutorService executor) {
            this.executor = executor;
        }

        boolean awaitBodyCancelled() {
            try {
                bodyCancelled.get(5, TimeUnit.SECONDS);
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public CompletableFuture<Void> execute(AsyncExecuteRequest request) {
            SdkHttpFullResponse.Builder response = SdkHttpFullResponse.builder().statusCode(200).putHeader("ETag", "\"etag\"");
            if (request.request().method() == SdkHttpMethod.PUT) {
                ByteArrayOutputStream received = new ByteArrayOutputStream();
                return SdkPublisher.adapt(request.requestContentPublisher())
                        .subscribe(buffer -> {
                            byte[] bytes = new byte[buffer.remaining()];
                            buffer.get(bytes);
                            received.write(bytes, 0, bytes.length);
                        })
                        .thenRun(() -> {
                            body = received.toByteArray();
                            // S3EC stores its encryption metadata in user metadata headers.
                            request.request().headers().forEach((name, values) -> {
                                if (name.toLowerCase().startsWith("x-amz-meta-")) {
                                    metadata.put(name, values.get(0));
                                }
                            });
                            request.responseHandler().onHeaders(response.build());
                            request.responseHandler().onStream(AsyncRequestBody.empty());
                        });
            }

            metadata.forEach(response::putHeader);
            response.putHeader("Content-Length", String.valueOf(body.length));
            bodyCancelled = new CompletableFuture<>();
            CompletableFuture<Void> cancelled = bodyCancelled;
            request.responseHandler().onHeaders(response.build());
            request.responseHandler().onStream(new OnDemandBody(body, executor, cancelled));
            return CompletableFuture.completedFuture(null);
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
     * Emits the body in 64 KiB chunks only as they are requested, like a real connection applying
     * backpressure, and completes {@code cancelled} if the subscriber cancels.
     */
    private static final class OnDemandBody implements SdkPublisher<ByteBuffer> {
        private final byte[] body;
        private final ExecutorService executor;
        private final CompletableFuture<Void> cancelled;

        OnDemandBody(byte[] body, ExecutorService executor, CompletableFuture<Void> cancelled) {
            this.body = body;
            this.executor = executor;
            this.cancelled = cancelled;
        }

        @Override
        public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
            subscriber.onSubscribe(new Subscription() {
                private int position;

                @Override
                public void request(long n) {
                    // Deliver on another thread so onNext never re-enters the caller of request().
                    executor.execute(() -> {
                        synchronized (this) {
                            for (long i = 0; i < n && !cancelled.isDone(); i++) {
                                if (position >= body.length) {
                                    if (position++ == body.length) {
                                        subscriber.onComplete();
                                    }
                                    return;
                                }
                                int length = Math.min(64 * 1024, body.length - position);
                                subscriber.onNext(ByteBuffer.wrap(body, position, length).slice());
                                position += length;
                            }
                        }
                    });
                }

                @Override
                public void cancel() {
                    cancelled.complete(null);
                }
            });
        }
    }
}
