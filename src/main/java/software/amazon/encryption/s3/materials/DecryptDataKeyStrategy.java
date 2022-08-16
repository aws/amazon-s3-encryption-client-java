package software.amazon.encryption.s3.materials;

import java.security.GeneralSecurityException;

public interface DecryptDataKeyStrategy {
    boolean isLegacy();

    String keyProviderInfo();

    byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey)
            throws GeneralSecurityException;
}
