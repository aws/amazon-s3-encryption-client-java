package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.materials.EncryptionMaterials;

@FunctionalInterface
public interface MultipartContentEncryptionStrategy {
    MultipartEncryptedContent initMultipartEncryption(EncryptionMaterials materials);
}
