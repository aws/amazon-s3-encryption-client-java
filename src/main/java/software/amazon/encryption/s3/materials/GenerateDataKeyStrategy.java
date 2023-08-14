package software.amazon.encryption.s3.materials;

public interface GenerateDataKeyStrategy {
    String keyProviderInfo();

    EncryptionMaterials generateDataKey(EncryptionMaterials materials);
}
