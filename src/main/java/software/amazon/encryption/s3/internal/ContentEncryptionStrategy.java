package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.materials.EncryptionMaterials;

import java.io.InputStream;

public interface ContentEncryptionStrategy {
    EncryptedContent encryptContent(EncryptionMaterials materials, InputStream content);

    EncryptedContent encryptContent(EncryptionMaterials materials);
}
