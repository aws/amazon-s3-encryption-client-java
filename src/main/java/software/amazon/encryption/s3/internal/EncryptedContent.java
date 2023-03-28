package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.async.AsyncRequestBody;

import javax.crypto.Cipher;
import java.io.InputStream;

public class EncryptedContent {

    private InputStream _ciphertext;
    private AsyncRequestBody _encryptedRequestBody;
    private long _ciphertextLength = -1;
    private byte[] _iv;

    // TODO: Look for Better ways to handle Cipher for Multipart Uploads.
    private Cipher _cipher;

    public EncryptedContent(final byte[] iv, final AsyncRequestBody encryptedRequestBody, final long ciphertextLength) {
        _iv = iv;
        _encryptedRequestBody = encryptedRequestBody;
        _ciphertextLength = ciphertextLength;
    }

    public EncryptedContent(final byte[] iv, Cipher cipher) {
        this._iv = iv;
        this._cipher = cipher;
    }

    public Cipher getCipher() {
        return _cipher;
    }

    public byte[] getIv() {
        return _iv;
    }

    public InputStream getCiphertext() {
        return _ciphertext;
    }

    public long getCiphertextLength() {
        return _ciphertextLength;
    }

    public AsyncRequestBody getAsyncCiphertext() {
        return _encryptedRequestBody;
    }

}
