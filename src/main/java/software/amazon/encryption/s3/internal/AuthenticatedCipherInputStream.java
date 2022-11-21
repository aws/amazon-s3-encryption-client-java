package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientSecurityException;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

public class AuthenticatedCipherInputStream extends CipherInputStream {

    public AuthenticatedCipherInputStream(InputStream inputStream, Cipher cipher) {
        super(inputStream, cipher);
    }

    /**
     * Authenticated ciphers call doFinal upon the last read,
     * there is no need to do so upon close.
     * @throws IOException from the wrapped InputStream
     */
    @Override
    public void close() throws IOException {
        in.close();
        currentPosition = maxPosition = 0;
        abortIfNeeded();
    }

    @Override
    protected int endOfFileReached() {
        eofReached = true;
        try {
            outputBuffer = cipher.doFinal();
            if (outputBuffer == null) {
                return -1;
            }
            currentPosition = 0;
            return maxPosition = outputBuffer.length;
        } catch (GeneralSecurityException exception) {
            // In an authenticated scheme, this indicates a security
            // exception
            throw new S3EncryptionClientSecurityException(exception.getMessage(), exception);
        }
    }
}
