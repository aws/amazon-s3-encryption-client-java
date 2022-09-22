package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.io.ReleasableInputStream;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

import java.io.InputStream;
import java.security.SecureRandom;

/**
 * Default (AES-GCM) content strategy for encrypting/decrypting
 * objects using a CipherLiteStream.
 */
public class StreamingAesGcmContentStrategy implements ContentEncryptionStrategy, ContentDecryptionStrategy {

    final private SecureRandom _secureRandom;

    private StreamingAesGcmContentStrategy(Builder builder) {
        this._secureRandom = builder._secureRandom;
    }

    public static Builder builder() { return new Builder(); }

    @Override
    public EncryptedContent encryptContent(final EncryptionMaterials materials, final InputStream inputStream) {
        final byte[] nonce = new byte[materials.algorithmSuite().nonceLengthBytes()];
        _secureRandom.nextBytes(nonce);
        final InputStream cipherStream = getCipherLiteInputStreamForEncryption(inputStream, materials, nonce);
        final long ciphertextLength = materials.ciphertextLength();
        return new EncryptedContent(cipherStream, ciphertextLength, nonce);
    }

    @Override
    public InputStream decryptContent(ContentMetadata contentMetadata, DecryptionMaterials materials, InputStream ciphertext) {
        return getCipherLiteInputStreamForDecryption(ciphertext, materials, contentMetadata.contentNonce());
    }

    private InputStream getCipherLiteInputStreamForDecryption(final InputStream inputStream, DecryptionMaterials materials, byte[] nonce) {
        final CipherLite cipherLite = CipherLiteFactory.newCipherLiteForDecryption(materials, nonce);
        return new CipherLiteInputStream(inputStream, cipherLite);
    }

    private InputStream getCipherLiteInputStreamForEncryption(final InputStream inputStream, EncryptionMaterials materials, byte[] nonce) {
        final CipherLite cipherLite = CipherLiteFactory.newCipherLiteForEncryption(materials, nonce);
        final InputStream releasableInputStream = ReleasableInputStream.wrap(inputStream);
        // TODO: Full stream choosing logic
        final LengthCheckInputStream lengthCheckInputStream = new LengthCheckInputStream(releasableInputStream, materials.plaintextLength(), LengthCheckInputStream.EXCLUDE_SKIPPED_BYTES);
        return new CipherLiteInputStream(lengthCheckInputStream, cipherLite);
    }

    public static class Builder {
        private SecureRandom _secureRandom = new SecureRandom();

        private Builder() {}

        public Builder secureRandom(SecureRandom secureRandom) {
            _secureRandom = secureRandom;
            return this;
        }

        public StreamingAesGcmContentStrategy build() {
            return new StreamingAesGcmContentStrategy(this);
        }
    }
}
