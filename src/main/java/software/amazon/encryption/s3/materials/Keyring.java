package software.amazon.encryption.s3.materials;

public interface Keyring {
    EncryptionMaterials OnEncrypt(final EncryptionMaterials materials);
}
