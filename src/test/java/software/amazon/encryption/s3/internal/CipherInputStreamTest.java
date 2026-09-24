// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.crypto.NullCipher;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link CipherInputStream#skip(long)}.
 * <p>
 * A {@link NullCipher} is used so the cipher passes bytes through unchanged,
 * letting these tests assert the stream's buffering and skip semantics directly
 * on known plaintext.
 */
public class CipherInputStreamTest {

    private static CipherInputStream streamOf(byte[] data) {
        return new CipherInputStream(new ByteArrayInputStream(data), new NullCipher());
    }

    @Test
    public void testSkipWithinBufferedData() throws IOException {
        byte[] data = new byte[100];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        try (CipherInputStream stream = streamOf(data)) {
            // Prime the buffer by reading the first byte (index 0).
            assertEquals(0, stream.read());
            // Skip the next 10 bytes (indices 1..10), landing on index 11.
            assertEquals(10L, stream.skip(10));
            assertEquals(11, stream.read());
        }
    }

    @Test
    public void testSkipClampsToEndOfBufferedData() throws IOException {
        byte[] data = new byte[50];
        try (CipherInputStream stream = streamOf(data)) {
            // Prime the buffer: 50 bytes are now available (currentPosition advances to 1).
            stream.read();
            // Ask to skip far more than remains in the buffer; skip is clamped to
            // the buffered remainder (49) and never skips past it.
            long skipped = stream.skip(1_000_000L);
            assertEquals(49L, skipped);
            // The buffer is now exhausted; a further skip returns 0.
            assertEquals(0L, stream.skip(10));
        }
    }

    @Test
    public void testSkipZeroReturnsZero() throws IOException {
        byte[] data = new byte[10];
        try (CipherInputStream stream = streamOf(data)) {
            stream.read();
            assertEquals(0L, stream.skip(0));
            // Position is unchanged: the next read is index 1.
            assertEquals(0, stream.read());
        }
    }

    @Test
    public void testSkipNegativeReturnsZero() throws IOException {
        byte[] data = new byte[10];
        try (CipherInputStream stream = streamOf(data)) {
            stream.read();
            assertEquals(0L, stream.skip(-5));
        }
    }

    @Test
    public void testSkipHugeLongDoesNotOverflowAndClamps() throws IOException {
        // Regression test for the implicit long->int narrowing in skip():
        // a very large positive long (well beyond Integer.MAX_VALUE) must clamp
        // to the buffered remainder rather than truncate/overflow into a wrong
        // (possibly negative) position.
        byte[] data = new byte[64];
        try (CipherInputStream stream = streamOf(data)) {
            stream.read(); // buffer now holds 63 remaining bytes
            long skipped = stream.skip(Long.MAX_VALUE);
            assertEquals(63L, skipped);
            assertEquals(-1, stream.read()); // stream fully consumed
        }
    }
}
