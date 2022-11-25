package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class MultipartAesGcmContentStrategy implements ContentEncryptionStrategy {

    final private SecureRandom _secureRandom;

    private MultipartAesGcmContentStrategy(Builder builder) {
        this._secureRandom = builder._secureRandom;
    }

    public static Builder builder() {
        return new Builder();
    }

    // Creates a Cipher and return EncryptedContent with Cipher to perform Multipart Upload
    @Override
    public EncryptedContent encryptContent(EncryptionMaterials materials, InputStream content) {
        final AlgorithmSuite algorithmSuite = materials.algorithmSuite();

        final byte[] nonce = new byte[algorithmSuite.nonceLengthBytes()];
        _secureRandom.nextBytes(nonce);

        final String cipherName = algorithmSuite.cipherName();
        try {
            final Cipher cipher = Cipher.getInstance(cipherName);

            cipher.init(Cipher.ENCRYPT_MODE, materials.dataKey(),
                    new GCMParameterSpec(algorithmSuite.cipherTagLengthBits(), nonce));
            // Return Cipher
            return new EncryptedContent(nonce, cipher);
        } catch (GeneralSecurityException e) {
            throw new S3EncryptionClientException("Unable to " + cipherName + " content encrypt.", e);
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

        public MultipartAesGcmContentStrategy build() {
            return new MultipartAesGcmContentStrategy(this);
        }
    }
}
