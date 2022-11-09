package software.amazon.encryption.s3.legacy.internal;

import software.amazon.awssdk.core.io.SdkInputStream;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.io.IOException;
import java.io.InputStream;

/**
 * Reads only a specific range of bytes from the underlying input stream.
 */
public class AdjustedRangeInputStream extends SdkInputStream {
    private final InputStream decryptedContents;
    private long virtualAvailable;
    private boolean closed;
    private final int SYMMETRIC_CIPHER_BLOCK_SIZE_BYTES = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherBlockSizeBytes();

    /**
     * Creates a new DecryptedContentsInputStream object.
     *
     * @param objectContents The input stream containing the object contents retrieved from S3
     * @param rangeBeginning The position of the left-most byte desired by the user
     * @param rangeEnd       The position of the right-most byte desired by the user
     * @throws IOException If there are errors skipping to the left-most byte desired by the user.
     */
    public AdjustedRangeInputStream(InputStream objectContents, long rangeBeginning, long rangeEnd) throws IOException {
        this.decryptedContents = objectContents;
        this.closed = false;
        initializeForRead(rangeBeginning, rangeEnd);
    }

    /**
     * Skip to the start location of the range of bytes desired by the user.
     */
    private void initializeForRead(long rangeBeginning, long rangeEnd) throws IOException {
        // To get to the left-most byte desired by a user, we must skip over the 16 bytes of the
        // preliminary cipher block, and then possibly skip a few more bytes into the next block
        // to where the left-most byte is located.
        int numBytesToSkip;
        if (rangeBeginning < SYMMETRIC_CIPHER_BLOCK_SIZE_BYTES) {
            numBytesToSkip = (int) rangeBeginning;
        } else {
            int offsetIntoBlock = (int) (rangeBeginning % SYMMETRIC_CIPHER_BLOCK_SIZE_BYTES);
            numBytesToSkip = SYMMETRIC_CIPHER_BLOCK_SIZE_BYTES + offsetIntoBlock;
        }
        if (numBytesToSkip != 0) {
            // Skip to the left-most desired byte.  The read() method is used instead of the skip() method
            // since the skip() method will not block if the underlying input stream is waiting for more input.
            while (numBytesToSkip > 0) {
                this.decryptedContents.read();
                numBytesToSkip--;
            }
        }
        // The number of bytes the user may read is equal to the number of the bytes in the range.
        // Note that the range includes the endpoints.
        this.virtualAvailable = (rangeEnd - rangeBeginning) + 1;
    }

    @Override
    public int read() throws IOException {
        abortIfNeeded();
        int result;
        // If there are no more available bytes, then we are at the end of the stream.
        if (this.virtualAvailable <= 0) {
            result = -1;
        } else {
            // Otherwise, read a byte.
            result = this.decryptedContents.read();
        }

        // If we have not reached the end of the stream, decrement the number of available bytes.
        if (result != -1) {
            this.virtualAvailable--;
        } else {
            // If we are at the end of the stream, close it.
            this.virtualAvailable = 0;
            close();
        }

        return result;
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        abortIfNeeded();
        int numBytesRead;
        // If no more bytes are available, do not read any bytes into the buffer
        if (this.virtualAvailable <= 0) {
            numBytesRead = -1;
        } else {
            // If the desired read length is greater than the number of available bytes,
            // shorten the read length to the number of available bytes.
            if (length > this.virtualAvailable) {
                length = (int) this.virtualAvailable;
            }
            // Read bytes into the buffer.
            numBytesRead = this.decryptedContents.read(buffer, offset, length);
        }
        // If we were able to read bytes, decrement the number of bytes available to be read.
        if (numBytesRead != -1) {
            this.virtualAvailable -= numBytesRead;
        } else {
            // If we've reached the end of the stream, close it
            this.virtualAvailable = 0;
            close();
        }
        return numBytesRead;
    }

    @Override
    public int available() throws IOException {
        abortIfNeeded();
        int available = this.decryptedContents.available();
        if (available < this.virtualAvailable) {
            return available;
        } else {
            // Limit the number of bytes available to the number
            // of bytes remaining in the range.
            return (int) this.virtualAvailable;
        }
    }

    @Override
    public void close() throws IOException {
        // If not already closed, then close the input stream.
        if (!this.closed) {
            this.closed = true;
            // if the user read to the end of the virtual stream, then drain
            // the wrapped stream so the HTTP client can keep this connection
            // alive if possible.
            // This should not have too much overhead since if we've reached the
            // end of the virtual stream, there should be at most 31 bytes left
            // (2 * SYMMETRIC_CIPHER_BLOCK_SIZE_BYTES - 1) in the
            // stream.
            // See: RangedGetUtils#getCipherBlockUpperBound
            if (this.virtualAvailable == 0) {
                IoUtils.drainInputStream(decryptedContents);
            }
            this.decryptedContents.close();
        }
        abortIfNeeded();
    }

    @Override
    protected InputStream getWrappedInputStream() {
        return decryptedContents;
    }
}