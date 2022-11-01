package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.DecryptionMaterials;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * This class will decrypt (only) data using AES/CTR while Ranged-Get is enabled
 */
public class AesCtrContentStrategy implements ContentDecryptionStrategy {

    private AesCtrContentStrategy(Builder builder) {}

    public static Builder builder() { return new Builder(); }

    @Override
    public InputStream decryptContent(ContentMetadata contentMetadata, DecryptionMaterials materials,
                                      InputStream ciphertextStream, String contentRange) {
        long[] desiredRange = RangedGetUtils.getRange(materials.s3Request().range());
        long[] cryptoRange = RangedGetUtils.getCryptoRange(materials.s3Request().range());
        AlgorithmSuite algorithmSuite = AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF;
        SecretKey contentKey = new SecretKeySpec(materials.plaintextDataKey(), algorithmSuite.dataKeyAlgorithm());
        byte[] iv = contentMetadata.contentNonce();
        iv = AesCtrUtils.adjustIV(iv, cryptoRange[0]);
        try {
            // TODO: Allow configurable Cryptographic provider
            final Cipher cipher = Cipher.getInstance(algorithmSuite.cipherName());
            cipher.init(Cipher.DECRYPT_MODE, contentKey, new IvParameterSpec(iv));
            InputStream plaintext = new CbcCipherInputStream(ciphertextStream, cipher);
            return RangedGetUtils.adjustToDesiredRange(plaintext, desiredRange, contentRange, algorithmSuite.cipherTagLengthBits());
        } catch (GeneralSecurityException ex) {
            throw new S3EncryptionClientException("Unable to build cipher: " + ex.getMessage()
                    + "\nMake sure you have the JCE unlimited strength policy files installed and "
                    + "configured for your JVM.", ex);
        }
    }

    public static class Builder {
        private Builder() {}

        public AesCtrContentStrategy build() {
            return new AesCtrContentStrategy(this);
        }
    }
}
