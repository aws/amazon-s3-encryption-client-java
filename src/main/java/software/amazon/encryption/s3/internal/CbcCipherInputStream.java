package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.io.SdkFilterInputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.io.InputStream;

/**
 * A cipher stream for decrypting CBC encrypted data. There is nothing particularly
 * specific to CBC, but other algorithms may require additional considerations.
 */
public class CbcCipherInputStream extends SdkFilterInputStream {
    private static final int MAX_RETRY_COUNT = 1000;
    private static final int DEFAULT_IN_BUFFER_SIZE = 512;
    private final Cipher cipher;

    private boolean eofReached;
    private byte[] inputBuffer;
    private byte[] outputBuffer;
    private int currentPosition;
    private int maxPosition;

    public CbcCipherInputStream(InputStream inputStream, Cipher cipher) {
        super(inputStream);
        this.cipher = cipher;
        this.inputBuffer = new byte[DEFAULT_IN_BUFFER_SIZE];
    }

    @Override
    public int read() throws IOException {
        if (!readNextChunk()) {
            return -1;
        }
        return ((int) outputBuffer[currentPosition++] & 0xFF);
    }

    @Override
    public int read(byte b[]) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte buf[], int off, int target_len) throws IOException {
        if (!readNextChunk()) {
            return -1;
        }
        if (target_len <= 0) {
            return 0;
        }
        int len = maxPosition - currentPosition;
        if (target_len < len) {
            len = target_len;
        }
        System.arraycopy(outputBuffer, currentPosition, buf, off, len);
        currentPosition += len;
        return len;
    }

    private boolean readNextChunk() throws IOException {
        if (currentPosition >= maxPosition) {
            // all buffered data has been read, let's get some more
            if (eofReached) {
                return false;
            }
            int retryCount = 0;
            int len;
            do {
                if (retryCount > MAX_RETRY_COUNT) {
                    throw new IOException("Exceeded maximum number of attempts to read next chunk of data");
                }
                len = nextChunk();
                // if buf != null, it means that data is being read off of the InputStream
                if (outputBuffer == null) {
                    retryCount++;
                }
            } while (len == 0);

            if (len == -1) {
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
     *         stream.
     * @throws IOException
     *             if there is an IO exception from the underlying input stream
     */
    private int nextChunk() throws IOException {
        abortIfNeeded();
        if (eofReached) {
            return -1;
        }
        outputBuffer = null;
        int len = in.read(inputBuffer);
        if (len == -1) {
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
        outputBuffer = cipher.update(inputBuffer, 0, len);
        currentPosition = 0;
        return maxPosition = (outputBuffer == null ? 0 : outputBuffer.length);
    }
}
