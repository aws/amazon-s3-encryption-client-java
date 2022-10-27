package software.amazon.encryption.s3.legacy.internal;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.CbcCipherInputStream;
import software.amazon.encryption.s3.internal.ContentDecryptionStrategy;
import software.amazon.encryption.s3.internal.ContentMetadata;
import software.amazon.encryption.s3.materials.DecryptionMaterials;

/**
 * This class will decrypt (only) data using AES/CBC
 */
public class AesCbcContentStrategy implements ContentDecryptionStrategy {

    private AesCbcContentStrategy(Builder builder) {}

    public static Builder builder() { return new Builder(); }

    @Override
    public InputStream decryptContent(ContentMetadata contentMetadata, DecryptionMaterials materials,
                                      InputStream ciphertextStream) {
        AlgorithmSuite algorithmSuite = contentMetadata.algorithmSuite();
        SecretKey contentKey = new SecretKeySpec(materials.plaintextDataKey(), algorithmSuite.dataKeyAlgorithm());
        byte[] iv = contentMetadata.contentNonce();
        try {
            // TODO: Allow configurable Cryptographic provider
            final Cipher cipher = Cipher.getInstance(materials.algorithmSuite().cipherName());
            cipher.init(Cipher.DECRYPT_MODE, contentKey, new IvParameterSpec(iv));
            return new CbcCipherInputStream(ciphertextStream, cipher);
        } catch (GeneralSecurityException ex) {
            throw new S3EncryptionClientException("Unable to build cipher: " + ex.getMessage()
                    + "\nMake sure you have the JCE unlimited strength policy files installed and "
                    + "configured for your JVM.", ex);
        }
    }

    public static class Builder {
        private Builder() {}

        public AesCbcContentStrategy build() {
            return new AesCbcContentStrategy(this);
        }
    }
}
