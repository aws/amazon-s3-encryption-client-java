// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.io.SdkFilterInputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.io.InputStream;

/**
 * A cipher stream for encrypting or decrypting data using an unauthenticated block cipher.
 */
public class CipherInputStream extends SdkFilterInputStream {
    private static final int MAX_RETRY_COUNT = 1000;
    private static final int DEFAULT_IN_BUFFER_SIZE = 512;
    protected final Cipher cipher;

    protected boolean eofReached;
    protected byte[] inputBuffer;
    protected byte[] outputBuffer;
    protected int currentPosition;
    protected int maxPosition;

    public CipherInputStream(InputStream inputStream, Cipher cipher) {
        super(inputStream);
        this.cipher = cipher;
        this.inputBuffer = new byte[DEFAULT_IN_BUFFER_SIZE];
    }

    @Override
    public int read() throws IOException {
        if (!readNextChunk()) {
            return -1;
        }
        // Cast the last byte to int with a value between 0-255, masking out the
        // higher bits. In other words, this is abs(x % 256).
        return ((int) outputBuffer[currentPosition++] & 0xFF);
    }

    @Override
    public int read(byte buffer[]) throws IOException {
        return read(buffer, 0, buffer.length);
    }

    @Override
    public int read(byte buffer[], int off, int targetLength) throws IOException {
        if (!readNextChunk()) {
            return -1;
        }
        if (targetLength <= 0) {
            return 0;
        }
        int length = maxPosition - currentPosition;
        if (targetLength < length) {
            length = targetLength;
        }
        System.arraycopy(outputBuffer, currentPosition, buffer, off, length);
        currentPosition += length;
        return length;
    }

    private boolean readNextChunk() throws IOException {
        if (currentPosition >= maxPosition) {
            // All buffered data has been read, let's get some more
            if (eofReached) {
                return false;
            }
            int retryCount = 0;
            int length;
            do {
                if (retryCount > MAX_RETRY_COUNT) {
                    throw new IOException("Exceeded maximum number of attempts to read next chunk of data");
                }
                length = nextChunk();
                // If outputBuffer != null, it means that data is being read off of the InputStream
                if (outputBuffer == null) {
                    retryCount++;
                }
            } while (length == 0);

            if (length == -1) {
                return false;
            }
        }
        return true;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Note: This implementation will only skip up to the end of the buffered
     * data, potentially skipping 0 bytes.
     */
    @Override
    public long skip(long n) {
        abortIfNeeded();
        int available = maxPosition - currentPosition;
        if (n > available) {
            n = available;
        }
        if (n < 0) {
            return 0;
        }
        currentPosition += n;
        return n;
    }

    @Override
    public int available() {
        abortIfNeeded();
        return maxPosition - currentPosition;
    }

    @Override
    public void close() throws IOException {
        in.close();
        try {
            // Throw away the unprocessed data
            cipher.doFinal();
        } catch (BadPaddingException | IllegalBlockSizeException ex) {
            // Swallow the exception
        }
        currentPosition = maxPosition = 0;
        abortIfNeeded();
    }

    @Override
    public boolean markSupported() {
        return false;
    }

    @Override
    public void mark(int readlimit) {
        // mark/reset not supported
    }

    @Override
    public void reset() throws IOException {
        throw new IOException("mark/reset not supported");
    }

    /**
     * Reads and process the next chunk of data into memory.
     *
     * @return the length of the data chunk read and processed, or -1 if end of
     * stream.
     * @throws IOException if there is an IO exception from the underlying input stream
     */
    protected int nextChunk() throws IOException {
        abortIfNeeded();
        if (eofReached) {
            return -1;
        }
        outputBuffer = null;
        int length = in.read(inputBuffer);
        if (length == -1) {
            return endOfFileReached();
        }
        outputBuffer = cipher.update(inputBuffer, 0, length);
        currentPosition = 0;
        return maxPosition = (outputBuffer == null ? 0 : outputBuffer.length);
    }

    protected int endOfFileReached() {
        eofReached = true;
        try {
            outputBuffer = cipher.doFinal();
            if (outputBuffer == null) {
                return -1;
            }
            currentPosition = 0;
            return maxPosition = outputBuffer.length;
        } catch (IllegalBlockSizeException | BadPaddingException ignore) {
            // Swallow exceptions
        }
        return -1;

    }
}
