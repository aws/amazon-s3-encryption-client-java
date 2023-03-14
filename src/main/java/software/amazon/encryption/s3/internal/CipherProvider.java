package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.CryptographicMaterials;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Composes a CMM to provide S3 specific functionality
 */
public class CipherProvider {

    private final CryptographicMaterialsManager cmm;

    public CipherProvider(final CryptographicMaterialsManager cmm) {
        this.cmm = cmm;
    }

    public static Cipher createAndInitCipher(final CryptographicMaterials materials, byte[] iv) {
        try {
            Cipher cipher = CryptoFactory.createCipher(materials.algorithmSuite().cipherName(), materials.cryptoProvider());
            switch (materials.algorithmSuite()) {
                case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
                    cipher.init(materials.opMode(), materials.dataKey(), new GCMParameterSpec(materials.algorithmSuite().cipherTagLengthBits(), iv));
                    break;
                case ALG_AES_256_CTR_IV16_TAG16_NO_KDF:
                case ALG_AES_256_CBC_IV16_NO_KDF:
                    if (materials.opMode() == Cipher.ENCRYPT_MODE) {
                        throw new S3EncryptionClientException("Encryption is not supported for algorithm: " + materials.algorithmSuite().cipherName());
                    }
                    cipher.init(materials.opMode(), materials.dataKey(), new IvParameterSpec(iv));
                    break;
                default:
                    throw new S3EncryptionClientException("Unknown algorithm: " + materials.algorithmSuite().cipherName());
            }
            return cipher;
        } catch (Exception exception) {
            throw new S3EncryptionClientException(exception.getMessage(), exception);
        }
    }

}
