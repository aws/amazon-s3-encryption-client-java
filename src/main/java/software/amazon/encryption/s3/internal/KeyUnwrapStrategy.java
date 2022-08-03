package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.materials.DecryptionMaterials;

public interface KeyUnwrapStrategy {
    DecryptionMaterials unwrapKey(ContentMetadata contentMetadata);
}
