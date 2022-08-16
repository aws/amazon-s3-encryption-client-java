package software.amazon.encryption.s3.materials;

import java.util.List;

/**
 * Keyring defines the interface for wrapping data keys. A {@link CryptographicMaterialsManager} will use
 * keyrings to encrypt and decrypt data keys.
 */
public interface Keyring {
    EncryptionMaterials onEncrypt(final EncryptionMaterials materials);
    DecryptionMaterials onDecrypt(final DecryptionMaterials materials, final List<EncryptedDataKey> encryptedDataKeys);
}
