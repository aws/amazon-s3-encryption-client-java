package software.amazon.encryption.s3.legacy.internal;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.CipherInputStream;
import software.amazon.encryption.s3.internal.ContentDecryptionStrategy;
import software.amazon.encryption.s3.internal.ContentMetadata;
import software.amazon.encryption.s3.internal.CryptoFactory;
import software.amazon.encryption.s3.materials.DecryptionMaterials;

/**
 * This class will decrypt (only) data using AES/CBC or AES/CTR content decryption strategies
 */
public class UnauthenticatedContentStrategy implements ContentDecryptionStrategy {

    private UnauthenticatedContentStrategy(Builder builder) {
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public InputStream decryptContent(ContentMetadata contentMetadata, DecryptionMaterials materials,
                                      InputStream ciphertextStream) {
        long[] desiredRange = RangedGetUtils.getRange(materials.s3Request().range());
        long[] cryptoRange = RangedGetUtils.getCryptoRange(materials.s3Request().range());
        AlgorithmSuite algorithmSuite = contentMetadata.algorithmSuite();
        byte[] iv = contentMetadata.contentNonce();
        if (algorithmSuite == AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF) {
            iv = AesCtrUtils.adjustIV(iv, cryptoRange[0]);
        }
        SecretKey contentKey = new SecretKeySpec(materials.plaintextDataKey(), algorithmSuite.dataKeyAlgorithm());
        try {
            final Cipher cipher = CryptoFactory.createCipher(algorithmSuite.cipherName(), materials.cryptoProvider());
            cipher.init(Cipher.DECRYPT_MODE, contentKey, new IvParameterSpec(iv));
            InputStream plaintext = new CipherInputStream(ciphertextStream, cipher);
            return RangedGetUtils.adjustToDesiredRange(plaintext, desiredRange, contentMetadata.contentRange(), algorithmSuite.cipherTagLengthBits());
        } catch (GeneralSecurityException ex) {
            throw new S3EncryptionClientException("Unable to build cipher: " + ex.getMessage()
                    + "\nMake sure you have the JCE unlimited strength policy files installed and "
                    + "configured for your JVM.", ex);
        }
    }

    public static class Builder {
        private Builder() {
        }

        public UnauthenticatedContentStrategy build() {
            return new UnauthenticatedContentStrategy(this);
        }
    }
}
