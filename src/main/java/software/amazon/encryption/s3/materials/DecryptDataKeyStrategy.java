package software.amazon.encryption.s3.materials;

import java.security.GeneralSecurityException;

public interface DecryptDataKeyStrategy {
    boolean isLegacyUnauthenticated();

    String keyProviderInfo();

    byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey)
            throws GeneralSecurityException;
}
