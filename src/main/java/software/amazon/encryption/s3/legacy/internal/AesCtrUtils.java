// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.legacy.internal;

import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.nio.ByteBuffer;

/**
 * Utilities for processing AES GCM encrypted data with AES CTR.
 * This is useful in scenarios such as ranged gets and when
 * re-reading the encrypted input stream.
 */
public class AesCtrUtils {
    public static final long MAX_GCM_BLOCKS = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherMaxContentLengthBits() >> 7; // 2^32 - 2
    public static final int CIPHER_BLOCK_SIZE = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherBlockSizeBytes();

    public static byte[] adjustIV(byte[] iv, long byteOffset) {
        // Currently only support iv of length 12 for AES/GCM.
        // Anything else is quite a bit complicated.
        if (iv.length != 12) {
            throw new UnsupportedOperationException();
        }
        final int blockSizeBytes = CIPHER_BLOCK_SIZE;
        final long blockOffset = byteOffset / blockSizeBytes;
        if (blockOffset * blockSizeBytes != byteOffset) {
            throw new IllegalArgumentException("Expecting byteOffset to be multiple of 16, but got blockOffset=" +
                    blockOffset + ", blockSize=" + blockSizeBytes + ", byteOffset=" + byteOffset);
        }
        byte[] J0 = computeJ0(iv);
        return incrementBlocks(J0, blockOffset);
    }

    /**
     * See <a href=
     * "http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf">
     * NIST Special Publication 800-38D.</a> for the definition of J0, the
     * "pre-counter block".
     * <p>
     * Reference: <a href=
     * "https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/crypto/modes/GCMBlockCipher.java"
     * >GCMBlockCipher.java</a>
     */
    private static byte[] computeJ0(byte[] iv) {
        final int blockSizeBytes = CIPHER_BLOCK_SIZE;
        byte[] J0 = new byte[blockSizeBytes];
        System.arraycopy(iv, 0, J0, 0, iv.length);
        J0[blockSizeBytes - 1] = 0x01;
        return incrementBlocks(J0, 1);
    }

    /**
     * Increment the rightmost 32 bits of a 16-byte counter by the specified
     * delta. Both the specified delta and the resultant value must stay within
     * the capacity of 32 bits.
     *
     * @param counter    a 16-byte counter used in AES/CTR
     * @param blockDelta the number of blocks (16-byte) to increment
     */
    private static byte[] incrementBlocks(byte[] counter, long blockDelta) {
        if (blockDelta == 0) {
            return counter;
        }
        if (counter == null || counter.length != 16) {
            throw new IllegalArgumentException();
        }
        if (blockDelta > MAX_GCM_BLOCKS) {
            throw new IllegalStateException();
        }
        // Allocate 8 bytes for a long
        ByteBuffer bb = ByteBuffer.allocate(8);
        // Copy the right-most 32 bits from the counter
        for (int i = 12; i <= 15; i++) {
            bb.put(i - 8, counter[i]);
        }
        // increment by delta
        long val = bb.getLong() + blockDelta;
        if (val > MAX_GCM_BLOCKS) {
            throw new IllegalStateException(); // overflow 2^32-2
        }
        // This cast is necessary to ensure compatibility with Java 1.8/8
        // when compiling with a newer Java version than 8
        ((java.nio.Buffer) bb).rewind();
        // Get the incremented value (result) as an 8-byte array
        byte[] result = bb.putLong(val).array();
        // Copy the rightmost 32 bits from the resultant array to the input counter;
        System.arraycopy(result, 4, counter, 12, 4);
        return counter;
    }
}
