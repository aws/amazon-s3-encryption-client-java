package software.amazon.encryption.s3.materials;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public interface EncryptDataKeyStrategy {
    String keyProviderId();

    byte[] encryptDataKey(
            SecureRandom secureRandom,
            EncryptionMaterials materials
    ) throws GeneralSecurityException;
}
