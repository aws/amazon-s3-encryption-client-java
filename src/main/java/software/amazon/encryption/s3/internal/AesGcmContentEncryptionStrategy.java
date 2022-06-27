package software.amazon.encryption.s3.internal;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.PutEncryptedObjectPipeline.ContentEncryptionStrategy;
import software.amazon.encryption.s3.internal.PutEncryptedObjectPipeline.EncryptedContent;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

/**
 * This class will encrypt data according to the algorithm suite constants
 */
public class AesGcmContentEncryptionStrategy implements ContentEncryptionStrategy {

    final private SecureRandom _secureRandom;

    private AesGcmContentEncryptionStrategy(Builder builder) {
        this._secureRandom = builder._secureRandom;
    }

    public static Builder builder() { return new Builder(); }

    @Override
    public EncryptedContent encryptContent(EncryptionMaterials materials, byte[] content) {
        final AlgorithmSuite algorithmSuite = materials.algorithmSuite();

        final byte[] nonce = new byte[algorithmSuite.nonceLengthBytes()];
        _secureRandom.nextBytes(nonce);

        final String cipherName = algorithmSuite.cipherName();
        try {
            final Cipher cipher = Cipher.getInstance(cipherName);

            cipher.init(Cipher.ENCRYPT_MODE,
                    materials.dataKey(),
                    new GCMParameterSpec(algorithmSuite.cipherTagLengthBits(), nonce));

            EncryptedContent result = new EncryptedContent();
            result.nonce = nonce;
            result.ciphertext = cipher.doFinal(content);

            return result;
        } catch (NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | InvalidAlgorithmParameterException
                 | InvalidKeyException
                 | IllegalBlockSizeException
                 | BadPaddingException e) {
            throw new S3EncryptionClientException("Unable to " + cipherName + " content encrypt.", e);
        }
    }

    public static class Builder {
        private SecureRandom _secureRandom = new SecureRandom();

        private Builder() {}

        public Builder secureRandom(SecureRandom secureRandom) {
            _secureRandom = secureRandom;
            return this;
        }

        public AesGcmContentEncryptionStrategy build() {
            return new AesGcmContentEncryptionStrategy(this);
        }
    }
}
