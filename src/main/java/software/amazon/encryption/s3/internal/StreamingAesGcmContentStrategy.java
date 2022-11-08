package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class StreamingAesGcmContentStrategy implements ContentEncryptionStrategy, ContentDecryptionStrategy {

    final private SecureRandom _secureRandom;

    private StreamingAesGcmContentStrategy(Builder builder) {
        this._secureRandom = builder._secureRandom;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public EncryptedContent encryptContent(EncryptionMaterials materials, InputStream content) {
        if (materials.getPlaintextLength() > AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherMaxContentLengthBytes()) {
            throw new S3EncryptionClientException("The contentLength of the object you are attempting to encrypt exceeds" +
                    "the maximum length allowed for GCM encryption.");
        }

        final AlgorithmSuite algorithmSuite = materials.algorithmSuite();

        final byte[] nonce = new byte[algorithmSuite.nonceLengthBytes()];
        _secureRandom.nextBytes(nonce);

        final String cipherName = algorithmSuite.cipherName();
        try {
            final Cipher cipher = Cipher.getInstance(cipherName);

            cipher.init(Cipher.ENCRYPT_MODE, materials.dataKey(),
                    new GCMParameterSpec(algorithmSuite.cipherTagLengthBits(), nonce));

            final InputStream ciphertext = new AuthenticatedCipherInputStream(content, cipher);
            final long ciphertextLength = materials.getPlaintextLength() + algorithmSuite.cipherTagLengthBits() / 8;
            return new EncryptedContent(nonce, ciphertext, ciphertextLength);
        } catch (GeneralSecurityException e) {
            throw new S3EncryptionClientException("Unable to " + cipherName + " content encrypt.", e);
        }
    }

    @Override
    public InputStream decryptContent(ContentMetadata contentMetadata, DecryptionMaterials materials,
                                      InputStream ciphertextStream) {

        AlgorithmSuite algorithmSuite = contentMetadata.algorithmSuite();
        SecretKey contentKey = new SecretKeySpec(materials.plaintextDataKey(), algorithmSuite.dataKeyAlgorithm());
        final int tagLength = algorithmSuite.cipherTagLengthBits();
        byte[] iv = contentMetadata.contentNonce();
        try {
            // TODO: Allow configurable Cryptographic provider
            final Cipher cipher = Cipher.getInstance(algorithmSuite.cipherName());
            cipher.init(Cipher.DECRYPT_MODE, contentKey, new GCMParameterSpec(tagLength, iv));
            return new AuthenticatedCipherInputStream(ciphertextStream, cipher);
        } catch (GeneralSecurityException e) {
            throw new S3EncryptionClientException("Unable to " + algorithmSuite.cipherName() + " content decrypt.", e);
        }
    }

    public static class Builder {
        private SecureRandom _secureRandom = new SecureRandom();

        private Builder() {
        }

        /**
         * Note that this does NOT create a defensive copy of the SecureRandom object. Any modifications to the
         * object will be reflected in this Builder.
         */
        @SuppressFBWarnings(value = "EI_EXPOSE_REP")
        public Builder secureRandom(SecureRandom secureRandom) {
            _secureRandom = secureRandom;
            return this;
        }

        public StreamingAesGcmContentStrategy build() {
            return new StreamingAesGcmContentStrategy(this);
        }
    }
}
