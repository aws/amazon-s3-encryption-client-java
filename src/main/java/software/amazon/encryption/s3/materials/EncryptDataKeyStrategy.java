package software.amazon.encryption.s3.materials;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Map;

public interface EncryptDataKeyStrategy {
    String keyProviderId();

    default EncryptionMaterials modifyMaterials(EncryptionMaterials materials) {
        return materials;
    }

    byte[] encryptDataKey(
            SecureRandom secureRandom,
            EncryptionMaterials materials
    ) throws GeneralSecurityException;
}
