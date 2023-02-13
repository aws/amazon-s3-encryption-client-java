package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class StreamingAesGcmContentStrategy implements AsyncContentEncryptionStrategy, MultipartContentEncryptionStrategy {

    final private SecureRandom _secureRandom;

    private StreamingAesGcmContentStrategy(Builder builder) {
        this._secureRandom = builder._secureRandom;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public EncryptedContent initMultipartEncryption(EncryptionMaterials materials) {
        final byte[] nonce = new byte[materials.algorithmSuite().nonceLengthBytes()];
        final Cipher cipher = prepareCipher(materials, nonce);
        // Return Cipher
        return new EncryptedContent(nonce, cipher);
    }

    @Override
    public EncryptedContent encryptContent(EncryptionMaterials materials, AsyncRequestBody content) {
        if (materials.getPlaintextLength() > AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherMaxContentLengthBytes()) {
            throw new S3EncryptionClientException("The contentLength of the object you are attempting to encrypt exceeds" +
                    "the maximum length allowed for GCM encryption.");
        }

        final byte[] nonce = new byte[materials.algorithmSuite().nonceLengthBytes()];
        final Cipher cipher = prepareCipher(materials, nonce);

        AsyncRequestBody encryptedAsyncRequestBody = new CipherAsyncRequestBody(cipher, content, materials.getCiphertextLength());
        return new EncryptedContent(nonce, encryptedAsyncRequestBody, materials.getCiphertextLength());
    }

    private Cipher prepareCipher(EncryptionMaterials materials, byte[] nonce) {
        if (materials.getPlaintextLength() > AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherMaxContentLengthBytes()) {
            throw new S3EncryptionClientException("The contentLength of the object you are attempting to encrypt exceeds" +
                    "the maximum length allowed for GCM encryption.");
        }

        final AlgorithmSuite algorithmSuite = materials.algorithmSuite();

        _secureRandom.nextBytes(nonce);

        final String cipherName = algorithmSuite.cipherName();
        try {
            final Cipher cipher = CryptoFactory.createCipher(cipherName, materials.cryptoProvider());
            cipher.init(Cipher.ENCRYPT_MODE, materials.dataKey(),
                    new GCMParameterSpec(algorithmSuite.cipherTagLengthBits(), nonce));
            return cipher;
        } catch (GeneralSecurityException e) {
            throw new S3EncryptionClientException("Unable to prepare " + cipherName + " for content encryption.", e);
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
            if (secureRandom == null) {
                throw new S3EncryptionClientException("SecureRandom provided to StreamingAesGcmContentStrategy cannot be null");
            }
            _secureRandom = secureRandom;
            return this;
        }

        public StreamingAesGcmContentStrategy build() {
            return new StreamingAesGcmContentStrategy(this);
        }
    }
}
