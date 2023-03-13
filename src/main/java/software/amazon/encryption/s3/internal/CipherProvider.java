package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.CryptographicMaterials;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

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

    public static Cipher getCipher(final CryptographicMaterials materials, byte[] iv) {
        // TODO: This is shite
        int opmode;
        if (materials instanceof EncryptionMaterials) {
            opmode = Cipher.ENCRYPT_MODE;
        } else if (materials instanceof DecryptionMaterials) {
            opmode = Cipher.DECRYPT_MODE;
        } else {
            throw new S3EncryptionClientException("Unknown materials");
        }

        try {
            Cipher cipher = CryptoFactory.createCipher(materials.algorithmSuite().cipherName(), materials.cryptoProvider());
            switch (materials.algorithmSuite()) {
                case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
                    cipher.init(opmode, materials.dataKey(), new GCMParameterSpec(materials.algorithmSuite().cipherTagLengthBits(), iv));
                    break;
                case ALG_AES_256_CTR_IV16_TAG16_NO_KDF:
                    // TODO: For now, the IV has already been twiddled, but probably better to that here
//                    if (materials.algorithmSuite() == AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF) {
//                        if (materials.s3Request() instanceof GetObjectRequest) {
//                            long[] cryptoRange = RangedGetUtils.getCryptoRange(((GetObjectRequest) materials.s3Request()).range());
//                            iv = AesCtrUtils.adjustIV(iv, cryptoRange[0]);
//                        } else {
//                            throw new S3EncryptionClientException("AES-CTR cannot be used to encrypt!");
//                        }
//                    }
                case ALG_AES_256_CBC_IV16_NO_KDF:
                    cipher.init(opmode, materials.dataKey(), new IvParameterSpec(iv));
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
