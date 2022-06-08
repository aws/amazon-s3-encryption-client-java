package software.amazon.encryption.s3.materials;

public interface MaterialsManager {
    EncryptionMaterials getEncryptionMaterials(EncryptionMaterialsRequest request);
    DecryptionMaterials getDecryptionMaterials(DecryptionMaterialsRequest request);
}
