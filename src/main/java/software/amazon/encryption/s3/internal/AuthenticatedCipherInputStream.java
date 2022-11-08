package software.amazon.encryption.s3.internal;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.io.InputStream;

public class AuthenticatedCipherInputStream extends CipherInputStream {

    public AuthenticatedCipherInputStream(InputStream inputStream, Cipher cipher) {
        super(inputStream, cipher);
    }

    /**
     * Authenticated ciphers call doFinal upon the last read,
     * so no need to do so upon close
     * @throws IOException from the wrapped InputStream
     */
    @Override
    public void close() throws IOException {
        in.close();
        currentPosition = maxPosition = 0;
        abortIfNeeded();
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
            eofReached = true;
            // TODO: Factor out other shared code besides this try/catch
            try {
                outputBuffer = cipher.doFinal();
                if (outputBuffer == null) {
                    return -1;
                }
                currentPosition = 0;
                return maxPosition = outputBuffer.length;
            } catch (IllegalBlockSizeException ignore) {
                // Swallow exception
            } catch (BadPaddingException exception) {
                // In an authenticated scheme, this indicates a security
                // exception
                throw new SecurityException(exception);
            }
            return -1;
        }
        outputBuffer = cipher.update(inputBuffer, 0, length);
        currentPosition = 0;
        return maxPosition = (outputBuffer == null ? 0 : outputBuffer.length);
    }
}
