// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.legacy.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

public class AdjustedRangeSubscriberTest {

    /**
     * Records everything delivered downstream so tests can assert on bytes and
     * terminal signals.
     */
    private static class RecordingSubscriber implements Subscriber<ByteBuffer> {
        final ByteArrayOutputStream data = new ByteArrayOutputStream();
        final AtomicInteger completeCount = new AtomicInteger();
        final AtomicInteger onNextCount = new AtomicInteger();
        Throwable error;

        @Override
        public void onSubscribe(Subscription s) {
        }

        @Override
        public void onNext(ByteBuffer byteBuffer) {
            onNextCount.incrementAndGet();
            byte[] b = new byte[byteBuffer.remaining()];
            byteBuffer.get(b);
            data.write(b, 0, b.length);
        }

        @Override
        public void onError(Throwable t) {
            error = t;
        }

        @Override
        public void onComplete() {
            completeCount.incrementAndGet();
        }
    }

    private static ByteBuffer bytes(int start, int length) {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) {
            b[i] = (byte) (start + i);
        }
        return ByteBuffer.wrap(b);
    }

    @Test
    public void testFirstChunkSmallerThanSkipDoesNotCompleteOrThrow() throws Exception {
        // rangeBeginning=20 => numBytesToSkip=20, virtualAvailable=100
        RecordingSubscriber downstream = new RecordingSubscriber();
        AdjustedRangeSubscriber subscriber = new AdjustedRangeSubscriber(downstream, 20L, 119L);

        // First chunk (10 bytes) is smaller than the 20-byte skip.
        subscriber.onNext(bytes(0, 10));
        assertEquals(0, downstream.completeCount.get());
        assertNull(downstream.error);
        assertEquals(0, downstream.data.size());

        // Second chunk (10 bytes) exactly finishes the skip; still no data delivered.
        subscriber.onNext(bytes(10, 10));
        assertEquals(0, downstream.completeCount.get());
        assertEquals(0, downstream.data.size());

        // Third chunk carries the actual payload, which must now be delivered.
        subscriber.onNext(bytes(100, 100));
        assertArrayEquals(bytes(100, 100).array(), downstream.data.toByteArray());
    }

    @Test
    public void testEmptyFirstChunkIsSkippedNotTreatedAsCompletion() throws Exception {
        RecordingSubscriber downstream = new RecordingSubscriber();
        AdjustedRangeSubscriber subscriber = new AdjustedRangeSubscriber(downstream, 20L, 119L);

        // CipherSubscriber can emit an empty buffer; it must not complete the stream.
        subscriber.onNext(ByteBuffer.allocate(0));
        assertEquals(0, downstream.completeCount.get());
        assertNull(downstream.error);

        subscriber.onNext(bytes(0, 20)); // finish the skip
        subscriber.onNext(bytes(50, 100));
        assertArrayEquals(bytes(50, 100).array(), downstream.data.toByteArray());
    }

    @Test
    public void testSkipOnlyChunkSignalsEmptyOnNextToKeepDemandFlowing() throws Exception {
        // Under one-at-a-time (request(1)) demand, a chunk fully consumed by the skip must still
        // signal the wrapped subscriber, or downstream waits forever for the next element. The
        // subscriber forwards an empty buffer (no in-range data, but the demand chain advances).
        RecordingSubscriber downstream = new RecordingSubscriber();
        AdjustedRangeSubscriber subscriber = new AdjustedRangeSubscriber(downstream, 20L, 119L);

        subscriber.onNext(bytes(0, 10)); // 10 bytes < 20-byte skip: entirely skipped

        assertEquals(1, downstream.onNextCount.get(), "skip-only chunk must forward exactly one onNext");
        assertEquals(0, downstream.data.size(), "the forwarded onNext must carry no in-range bytes");
        assertEquals(0, downstream.completeCount.get(), "skip-only chunk must not complete the stream");
        assertNull(downstream.error);
    }

    @Test
    public void testChunkLargerThanSkipDeliversRemainder() throws Exception {
        RecordingSubscriber downstream = new RecordingSubscriber();
        AdjustedRangeSubscriber subscriber = new AdjustedRangeSubscriber(downstream, 20L, 119L);

        // A single 120-byte chunk: 20 skipped, 100 delivered.
        subscriber.onNext(bytes(0, 120));
        assertArrayEquals(bytes(20, 100).array(), downstream.data.toByteArray());
        assertFalse(downstream.completeCount.get() == 0);
    }
}
