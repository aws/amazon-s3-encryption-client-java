package software.amazon.encryption.s3.internal;

import java.io.InputStream;

public class EncryptedContent {

    private InputStream _ciphertext;
    private long _ciphertextLength;
    private byte[] _nonce;
    public EncryptedContent(final byte[] nonce, final InputStream ciphertext, final long ciphertextLength) {
        _nonce = nonce;
        _ciphertext = ciphertext;
        _ciphertextLength = ciphertextLength;
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
