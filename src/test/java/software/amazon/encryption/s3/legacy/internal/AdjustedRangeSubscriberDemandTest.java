// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.legacy.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

import software.amazon.awssdk.utils.async.InputStreamSubscriber;

/**
 * Exercises {@link AdjustedRangeSubscriber} through the subscriber chain used by a synchronous
 * ranged GET: a backpressure publisher feeds the subscriber, which wraps an
 * {@link InputStreamSubscriber} (the one behind {@code toBlockingInputStream()}). Reads are
 * timeout-bounded so a demand stall fails instead of hanging.
 */
public class AdjustedRangeSubscriberDemandTest {

    /** Reactive-streams publisher that respects request(n) and delivers chunks on its own thread. */
    private static class BackpressurePublisher implements Publisher<ByteBuffer> {
        private final ConcurrentLinkedQueue<ByteBuffer> chunks;
        private final ExecutorService exec = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "delivery");
            t.setDaemon(true);
            return t;
        });

        BackpressurePublisher(List<ByteBuffer> chunks) {
            this.chunks = new ConcurrentLinkedQueue<>(chunks);
        }

        @Override
        public void subscribe(Subscriber<? super ByteBuffer> s) {
            AtomicBoolean terminated = new AtomicBoolean(false);
            s.onSubscribe(new Subscription() {
                @Override
                public void request(long n) {
                    exec.submit(() -> {
                        for (long i = 0; i < n; i++) {
                            if (terminated.get()) {
                                return;
                            }
                            ByteBuffer b = chunks.poll();
                            if (b == null) {
                                if (terminated.compareAndSet(false, true)) {
                                    s.onComplete();
                                }
                                return;
                            }
                            s.onNext(b);
                        }
                    });
                }

                @Override
                public void cancel() {
                    terminated.set(true);
                    exec.shutdownNow();
                }
            });
        }
    }

    private static ByteBuffer bytes(int start, int length) {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) {
            b[i] = (byte) (start + i);
        }
        return ByteBuffer.wrap(b);
    }

    private static byte[] readAllWithTimeout(InputStream in, long timeoutSeconds) throws Exception {
        ExecutorService reader = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "reader");
            t.setDaemon(true);
            return t;
        });
        try {
            Future<byte[]> f = reader.submit(() -> {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] tmp = new byte[64];
                int n;
                while ((n = in.read(tmp)) != -1) {
                    out.write(tmp, 0, n);
                }
                return out.toByteArray();
            });
            return f.get(timeoutSeconds, TimeUnit.SECONDS);
        } finally {
            reader.shutdownNow();
        }
    }

    /** CTR case: first chunk smaller than the skip, then the payload. */
    @Test
    public void firstChunkSmallerThanSkip_deliversFullPayload() throws Exception {
        // rangeBeginning=20 => skip=20, rangeEnd=119 => virtualAvailable=100
        List<ByteBuffer> chunks = new ArrayList<>();
        chunks.add(bytes(0, 10));    // skipped
        chunks.add(bytes(10, 10));   // finishes the skip
        chunks.add(bytes(100, 100)); // payload

        InputStreamSubscriber iss = new InputStreamSubscriber();
        AdjustedRangeSubscriber ars = new AdjustedRangeSubscriber(iss, 20L, 119L);
        new BackpressurePublisher(chunks).subscribe(ars);

        byte[] out = readAllWithTimeout(iss, 10);
        assertEquals(100, out.length, "must receive the full in-range payload, not an empty stream");
        assertArrayEquals(bytes(100, 100).array(), out);
    }

    /** AES/CBC case: an empty first buffer (as CipherSubscriber emits) must not complete the stream. */
    @Test
    public void emptyFirstChunk_thenPayload_deliversFullPayload() throws Exception {
        List<ByteBuffer> chunks = new ArrayList<>();
        chunks.add(ByteBuffer.allocate(0)); // empty
        chunks.add(bytes(0, 20));           // finishes the skip
        chunks.add(bytes(50, 100));         // payload

        InputStreamSubscriber iss = new InputStreamSubscriber();
        AdjustedRangeSubscriber ars = new AdjustedRangeSubscriber(iss, 20L, 119L);
        new BackpressurePublisher(chunks).subscribe(ars);

        byte[] out = readAllWithTimeout(iss, 10);
        assertEquals(100, out.length, "empty first chunk must not truncate the stream");
        assertArrayEquals(bytes(50, 100).array(), out);
    }

    /** Many 1-byte chunks span the skip (heavy fragmentation), then a split payload. */
    @Test
    public void manyTinyChunksBeforeSkipCompletes_deliversFullPayload() throws Exception {
        List<ByteBuffer> chunks = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            chunks.add(bytes(i, 1)); // 20 x 1 byte == the skip
        }
        chunks.add(bytes(100, 40));
        chunks.add(bytes(140, 60));

        InputStreamSubscriber iss = new InputStreamSubscriber();
        AdjustedRangeSubscriber ars = new AdjustedRangeSubscriber(iss, 20L, 119L);
        new BackpressurePublisher(chunks).subscribe(ars);

        byte[] out = readAllWithTimeout(iss, 10);
        assertEquals(100, out.length);
        assertArrayEquals(bytes(100, 100).array(), out);
    }

    /** Single chunk larger than the skip: remainder delivered. */
    @Test
    public void singleChunkLargerThanSkip_deliversRemainder() throws Exception {
        List<ByteBuffer> chunks = new ArrayList<>();
        chunks.add(bytes(0, 120)); // 20 skipped, 100 in range

        InputStreamSubscriber iss = new InputStreamSubscriber();
        AdjustedRangeSubscriber ars = new AdjustedRangeSubscriber(iss, 20L, 119L);
        new BackpressurePublisher(chunks).subscribe(ars);

        byte[] out = readAllWithTimeout(iss, 10);
        assertArrayEquals(bytes(20, 100).array(), out);
    }

    /** Chunk exactly equal to the skip (the {@code >=} boundary), then the payload. */
    @Test
    public void chunkEqualToSkip_thenPayload_deliversFullPayload() throws Exception {
        List<ByteBuffer> chunks = new ArrayList<>();
        chunks.add(bytes(0, 20));    // exactly the skip
        chunks.add(bytes(100, 100)); // payload

        InputStreamSubscriber iss = new InputStreamSubscriber();
        AdjustedRangeSubscriber ars = new AdjustedRangeSubscriber(iss, 20L, 119L);
        new BackpressurePublisher(chunks).subscribe(ars);

        byte[] out = readAllWithTimeout(iss, 10);
        assertEquals(100, out.length, "chunk equal to skip must not truncate the stream");
        assertArrayEquals(bytes(100, 100).array(), out);
    }
}
