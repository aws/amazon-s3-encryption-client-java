package software.amazon.encryption.s3.legacy.internal;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.ContentDecryptionStrategy;
import software.amazon.encryption.s3.internal.ContentMetadata;
import software.amazon.encryption.s3.materials.DecryptionMaterials;

/**
 * This class will decrypt (only) data according for AES/CBC
 */
public class AesCbcContentStrategy implements ContentDecryptionStrategy {

    private AesCbcContentStrategy(Builder builder) {}

    public static Builder builder() { return new Builder(); }

    @Override
    public byte[] decryptContent(ContentMetadata contentMetadata, DecryptionMaterials materials, byte[] ciphertext) {
        AlgorithmSuite algorithmSuite = contentMetadata.algorithmSuite();
        SecretKey contentKey = new SecretKeySpec(materials.plaintextDataKey(), algorithmSuite.dataKeyAlgorithm());
        byte[] iv = contentMetadata.contentNonce();
        final Cipher cipher;
        byte[] plaintext;
        try {
            cipher = Cipher.getInstance(algorithmSuite.cipherName());
            cipher.init(Cipher.DECRYPT_MODE, contentKey, new IvParameterSpec(iv));
            plaintext = cipher.doFinal(ciphertext);
        } catch (NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | InvalidAlgorithmParameterException
                 | InvalidKeyException
                 | IllegalBlockSizeException
                 | BadPaddingException e) {
            throw new S3EncryptionClientException("Unable to " + algorithmSuite.cipherName() + " content decrypt.", e);
        }

        return plaintext;
    }

    public static class Builder {
        private Builder() {}

        public AesCbcContentStrategy build() {
            return new AesCbcContentStrategy(this);
        }
    }
}
