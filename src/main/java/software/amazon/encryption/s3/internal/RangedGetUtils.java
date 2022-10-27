package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Reads only a specific range of bytes from the underlying input stream.
 */
public class RangedGetUtils {

    public static long[] getRange(String range) {
        if (!range.matches("bytes=[0-9]+-[0-9]+")) {
            return null;
        }
        String[] rangeSplit = range.split("[-=]");
        long[] adjustedRange = new long[2];
        adjustedRange[0] = Integer.parseInt(rangeSplit[1]);
        adjustedRange[1] = Integer.parseInt(rangeSplit[2]);
        return adjustedRange;
    }

    public static String getCryptoRange(String desiredRange) {
        long[] range = getRange(desiredRange);
        // If range is invalid, then return null.
        if (range == null || range[0] > range[1]) {
            return null;
        }
        long[] adjustedCryptoRange = new long[2];
        adjustedCryptoRange[0] = getCipherBlockLowerBound(range[0]);
        adjustedCryptoRange[1] = getCipherBlockUpperBound(range[1]);
        return "bytes=" + adjustedCryptoRange[0] + "-" + adjustedCryptoRange[1];
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

    public static InputStream adjustToDesiredRange(InputStream plaintext, long[] range, String contentRange, int cipherTagLengthBits) {
        if (range == null || contentRange == null)
            return plaintext;

        final long instanceLength;
        int pos = contentRange.lastIndexOf("/");
        instanceLength = Long.parseLong(contentRange.substring(pos + 1));

        final long maxOffset = instanceLength - (cipherTagLengthBits / 8) - 1;
        if (range[1] > maxOffset) {
            range[1] = maxOffset;
            if (range[0] > range[1]) {
                // Close existing input stream to avoid resource leakage,
                // return empty input stream
                try {
                    if (plaintext != null)
                        plaintext.close();
                } catch (IOException e) {
                    throw new RuntimeException("Error while closing the Input Stream" + e.getMessage());
                }
                return new ByteArrayInputStream(new byte[0]);
            }
        }
        if (range[0] > range[1]) {
            // Make no modifications if range is invalid.
            return plaintext;
        }
        try {
            return new AdjustedRangeInputStream(plaintext, range[0], range[1]);
        } catch (IOException e) {
            throw new S3EncryptionClientException("Error adjusting output to desired byte range: " + e.getMessage());
        }
    }
}
