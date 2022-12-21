package software.amazon.encryption.s3.internal;

import javax.crypto.Cipher;
import java.io.InputStream;

public class EncryptedContent {

    private InputStream _ciphertext;
    private long _ciphertextLength;
    private byte[] _nonce;
    // TODO: Look for Better ways to handle Cipher for Multipart Uploads.
    private Cipher _cipher;
    public EncryptedContent(final byte[] nonce, final InputStream ciphertext, final long ciphertextLength) {
        _nonce = nonce;
        _ciphertext = ciphertext;
        _ciphertextLength = ciphertextLength;
    }

    public EncryptedContent(byte[] nonce, Cipher cipher) {
        this(nonce, null, 0);
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

}
