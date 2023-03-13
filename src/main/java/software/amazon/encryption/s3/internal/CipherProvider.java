package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.materials.CryptographicMaterials;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;

import javax.crypto.Cipher;

/**
 * Composes a CMM to provide S3 specific functionality
 */
public class CipherProvider {

    private final CryptographicMaterialsManager cmm;

    public CipherProvider(final CryptographicMaterialsManager cmm) {
        this.cmm = cmm;
    }

    public Cipher getCipher(final CryptographicMaterials materials) {
        return 

    }

}
