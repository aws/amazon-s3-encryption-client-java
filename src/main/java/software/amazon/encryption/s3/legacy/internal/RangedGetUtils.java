// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.legacy.internal;

import org.reactivestreams.Subscriber;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Utilities for processing Ranged Get functions.
 */
public class RangedGetUtils {

    public static long[] getRange(String range) {
        if (range == null) {
            return null;
        }
        if (!range.matches("^bytes=(\\d+-\\d+|\\d+-)$")) {
            return null;
        }
        String[] rangeSplit = range.substring(6).split("-");
        long[] adjustedRange = new long[2];
        adjustedRange[0] = Long.parseLong(rangeSplit[0]);
        adjustedRange[1] = (rangeSplit.length < 2 || rangeSplit[1].isEmpty()) ? Long.MAX_VALUE : Long.parseLong(rangeSplit[1]);
        return adjustedRange;
    }

    public static String getCryptoRangeAsString(String desiredRange) {
        long[] cryptoRange = RangedGetUtils.getCryptoRange(desiredRange);
        return cryptoRange == null ? null : "bytes=" + cryptoRange[0] + "-" + cryptoRange[1];
    }

    public static long[] getCryptoRange(String desiredRange) {
        long[] range = getRange(desiredRange);
        // If range is invalid, then return null.
        if (range == null || range[0] > range[1]) {
            return null;
        }
        long[] adjustedCryptoRange = new long[2];
        adjustedCryptoRange[0] = getCipherBlockLowerBound(range[0]);
        adjustedCryptoRange[1] = getCipherBlockUpperBound(range[1]);
        return adjustedCryptoRange;
    }

    private static long getCipherBlockLowerBound(long leftmostBytePosition) {
        long cipherBlockSize = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherBlockSizeBytes();
        long offset = leftmostBytePosition % cipherBlockSize;
        long lowerBound = leftmostBytePosition - offset - cipherBlockSize;
        return lowerBound < 0 ? 0 : lowerBound;
    }

    private static long getCipherBlockUpperBound(final long rightmostBytePosition) {
        long cipherBlockSize = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherBlockSizeBytes();
        long offset = cipherBlockSize - (rightmostBytePosition % cipherBlockSize);
        long upperBound = rightmostBytePosition + offset + cipherBlockSize;
        return upperBound < 0 ? Long.MAX_VALUE : upperBound;
    }

    private static long calculateMaxOffset(String contentRange, int cipherTagLengthBits) {
        final long instanceLength;
        int pos = contentRange.lastIndexOf("/");
        instanceLength = Long.parseLong(contentRange.substring(pos + 1));

        return instanceLength - (cipherTagLengthBits / 8) - 1;
    }

    public static Subscriber<? super ByteBuffer> adjustToDesiredRange(Subscriber<? super ByteBuffer> subscriber, long[] cryptoRange, String contentRange, int cipherTagLengthBits) {
        if (cryptoRange == null || contentRange == null) {
            return subscriber;
        }

        final long maxOffset = calculateMaxOffset(contentRange, cipherTagLengthBits);
        if (cryptoRange[1] > maxOffset) {
            cryptoRange[1] = maxOffset;
            if (cryptoRange[0] > cryptoRange[1]) {
                // When the beginning of the crypto range is after the max offset,
                // there is no data to read. The current implementation of
                // AdjustedRangeSubscriber handles this case itself,
                // but this might as well be a Null/Noop Subscriber
                try {
                    return new AdjustedRangeSubscriber(subscriber, cryptoRange[0], cryptoRange[1]);
                } catch (IOException e) {
                    throw new S3EncryptionClientException(e.getMessage());
                }
            }
        }
        if (cryptoRange[0] > cryptoRange[1]) {
            // Make no modifications if range is invalid.
            return subscriber;
        }
        try {
            return new AdjustedRangeSubscriber(subscriber, cryptoRange[0], cryptoRange[1]);
        } catch (IOException e) {
            throw new S3EncryptionClientException("Error adjusting output to desired byte range: " + e.getMessage());
        }
    }
}
