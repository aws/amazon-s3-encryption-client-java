package software.amazon.encryption.s3.materials;

import java.security.GeneralSecurityException;

public interface DecryptDataKeyStrategy {
    boolean isLegacy();

    String keyProviderId();

    byte[] decryptDataKey(DecryptionMaterials materials, EncryptedDataKey encryptedDataKey)
            throws GeneralSecurityException;
}
