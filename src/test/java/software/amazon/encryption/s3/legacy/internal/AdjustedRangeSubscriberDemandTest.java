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
 * Drives the REAL production topology for issue #517:
 *
 *   BackpressurePublisher  ->  AdjustedRangeSubscriber  ->  InputStreamSubscriber (== toBlockingInputStream)
 *
 * AdjustedRangeSubscriber forwards the upstream Subscription straight to the InputStreamSubscriber,
 * so demand is driven by the blocking InputStream reader on the shared subscription -- exactly the
 * synchronous S3EncryptionClient.getObject path. The publisher honors request(n) and delivers on a
 * separate thread, mimicking async S3 delivery. Each read is bounded by a timeout so that a
 * demand-stall (the suspected failure mode of a wrong fix) surfaces as a test failure, not a hang.
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

    /**
     * CTR case: a tiny non-empty first chunk (< skip), then a second small chunk finishing the skip,
     * then the payload. Must deliver the full in-range payload, not an empty stream.
     */
    @Test
    public void firstChunkSmallerThanSkip_deliversFullPayload() throws Exception {
        // rangeBeginning=20 => numBytesToSkip=20 ; rangeEnd=119 => virtualAvailable=100
        List<ByteBuffer> chunks = new ArrayList<>();
        chunks.add(bytes(0, 10));    // 10 bytes  -> entirely skipped
        chunks.add(bytes(10, 10));   // 10 bytes  -> finishes the 20-byte skip
        chunks.add(bytes(100, 100)); // 100 bytes -> the in-range payload

        InputStreamSubscriber iss = new InputStreamSubscriber();
        AdjustedRangeSubscriber ars = new AdjustedRangeSubscriber(iss, 20L, 119L);
        new BackpressurePublisher(chunks).subscribe(ars);

        byte[] out = readAllWithTimeout(iss, 10);
        assertEquals(100, out.length, "must receive the full in-range payload, not an empty stream");
        assertArrayEquals(bytes(100, 100).array(), out);
    }

    /**
     * AES/CBC (v1) case from the issue: CipherSubscriber emits an empty ByteBuffer first. The empty
     * buffer satisfies "chunk <= skip"; the fix must not treat it as completion and must keep demand
     * flowing so the payload still arrives.
     */
    @Test
    public void emptyFirstChunk_thenPayload_deliversFullPayload() throws Exception {
        List<ByteBuffer> chunks = new ArrayList<>();
        chunks.add(ByteBuffer.allocate(0)); // empty, as CipherSubscriber emits for CBC
        chunks.add(bytes(0, 20));           // finishes the 20-byte skip
        chunks.add(bytes(50, 100));         // in-range payload

        InputStreamSubscriber iss = new InputStreamSubscriber();
        AdjustedRangeSubscriber ars = new AdjustedRangeSubscriber(iss, 20L, 119L);
        new BackpressurePublisher(chunks).subscribe(ars);

        byte[] out = readAllWithTimeout(iss, 10);
        assertEquals(100, out.length, "empty first chunk must not truncate the stream");
        assertArrayEquals(bytes(50, 100).array(), out);
    }

    /**
     * Many tiny sub-skip chunks in a row (aggressive TLS/TCP fragmentation), then payload split
     * across several chunks. Exercises repeated empty-onNext forwarding.
     */
    @Test
    public void manyTinyChunksBeforeSkipCompletes_deliversFullPayload() throws Exception {
        List<ByteBuffer> chunks = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            chunks.add(bytes(i, 1)); // 20 x 1-byte chunks == the whole 20-byte skip
        }
        // payload 100 bytes, split
        chunks.add(bytes(100, 40));
        chunks.add(bytes(140, 60));

        InputStreamSubscriber iss = new InputStreamSubscriber();
        AdjustedRangeSubscriber ars = new AdjustedRangeSubscriber(iss, 20L, 119L);
        new BackpressurePublisher(chunks).subscribe(ars);

        byte[] out = readAllWithTimeout(iss, 10);
        assertEquals(100, out.length);
        assertArrayEquals(bytes(100, 100).array(), out);
    }

    /** Single chunk larger than the skip: 20 skipped, remainder delivered (regression guard). */
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

    /**
     * A chunk exactly equal to the remaining skip must be fully consumed (the {@code >=} boundary),
     * with the payload in the following chunk still delivered in full.
     */
    @Test
    public void chunkEqualToSkip_thenPayload_deliversFullPayload() throws Exception {
        List<ByteBuffer> chunks = new ArrayList<>();
        chunks.add(bytes(0, 20));    // exactly the 20-byte skip
        chunks.add(bytes(100, 100)); // in-range payload

        InputStreamSubscriber iss = new InputStreamSubscriber();
        AdjustedRangeSubscriber ars = new AdjustedRangeSubscriber(iss, 20L, 119L);
        new BackpressurePublisher(chunks).subscribe(ars);

        byte[] out = readAllWithTimeout(iss, 10);
        assertEquals(100, out.length, "chunk equal to skip must not truncate the stream");
        assertArrayEquals(bytes(100, 100).array(), out);
    }
}
