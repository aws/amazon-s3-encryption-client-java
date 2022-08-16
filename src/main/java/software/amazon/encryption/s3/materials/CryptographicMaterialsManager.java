package software.amazon.encryption.s3.materials;

public interface CryptographicMaterialsManager {
    EncryptionMaterials getEncryptionMaterials(EncryptionMaterialsRequest request);
    DecryptionMaterials decryptMaterials(DecryptMaterialsRequest request);
}
