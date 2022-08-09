package software.amazon.encryption.s3.materials;

import java.security.GeneralSecurityException;
import java.security.Key;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptedDataKey;

public interface DecryptDataKeyStrategy {
    boolean isLegacy();

    String keyProviderId();

    byte[] decryptDataKey(Key unwrappingKey, DecryptionMaterials materials, EncryptedDataKey encryptedDataKey)
            throws GeneralSecurityException;
}
