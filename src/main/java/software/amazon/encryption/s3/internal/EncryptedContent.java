package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.async.AsyncRequestBody;

import javax.crypto.Cipher;
import java.io.InputStream;

public class EncryptedContent {

    private InputStream _ciphertext;
    private AsyncRequestBody _asyncCiphertext;
    private long _ciphertextLength = -1;
    private byte[] _nonce;

    // TODO: Look for Better ways to handle Cipher for Multipart Uploads.
    private Cipher _cipher;

    public EncryptedContent(final byte[] nonce, final AsyncRequestBody asyncRequestBody, final long ciphertextLength) {
        _nonce = nonce;
        _asyncCiphertext = asyncRequestBody;
        _ciphertextLength = ciphertextLength;
    }
    public EncryptedContent(final byte[] nonce, final InputStream ciphertext, final long ciphertextLength) {
        _nonce = nonce;
        _ciphertext = ciphertext;
        _ciphertextLength = ciphertextLength;
    }

    public EncryptedContent(byte[] nonce, Cipher cipher) {
        this._nonce = nonce;
        this._cipher = cipher;
    }

    public Cipher getCipher() {
        return _cipher;
    }

    public byte[] getNonce() {
        return _nonce;
    }

    public InputStream getCiphertext() {
        return _ciphertext;
    }

    public long getCiphertextLength() {
        return _ciphertextLength;
    }

    public AsyncRequestBody getAsyncCiphertext() {
        return _asyncCiphertext;
    }

}
