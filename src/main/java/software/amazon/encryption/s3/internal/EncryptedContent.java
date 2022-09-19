package software.amazon.encryption.s3.internal;

import java.io.InputStream;

public class EncryptedContent {

    private byte[] _ciphertext;
    private byte[] _nonce;
    private InputStream _inputStream;
    private long _ciphertextLength;

    public EncryptedContent(byte[] ciphertext, byte[] nonce) {
        _ciphertext = ciphertext;
        _nonce = nonce;
        _ciphertextLength = ciphertext.length;
    }

    public EncryptedContent(final InputStream inputStream, long ciphertextLength, byte[] nonce) {
        _inputStream = inputStream;
        _ciphertextLength = ciphertextLength;
        _nonce = nonce;
    }

    public byte[] getCiphertext() {
        return _ciphertext;
    }

    public byte[] getNonce() {
        return _nonce;
    }
    public InputStream getInputStream() {
        return _inputStream;
    }

    public long getCiphertextLength() {
        return _ciphertextLength;
    }

}
