package software.amazon.encryption.s3.materials;

import java.util.List;

public interface Keyring {
    EncryptionMaterials onEncrypt(final EncryptionMaterials materials);
    DecryptionMaterials onDecrypt(final DecryptionMaterials materials, final List<EncryptedDataKey> encryptedDataKeys);
}
