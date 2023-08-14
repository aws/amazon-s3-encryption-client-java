package software.amazon.encryption.s3.materials;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public interface GenerateDataKeyStrategy {
    String keyProviderInfo();

    EncryptionMaterials generateDataKey(EncryptionMaterials materials);
}
