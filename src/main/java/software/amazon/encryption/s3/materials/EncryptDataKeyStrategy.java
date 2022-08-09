package software.amazon.encryption.s3.materials;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

public interface EncryptDataKeyStrategy {
    String keyProviderId();

    byte[] encryptDataKey(
            SecureRandom secureRandom,
            Key wrappingKey,
            EncryptionMaterials materials
    ) throws GeneralSecurityException;
}
