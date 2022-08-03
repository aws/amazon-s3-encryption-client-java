package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.materials.DecryptionMaterials;

@FunctionalInterface
public interface ContentDecryptionStrategy {
    byte[] decryptContent(ContentMetadata contentMetadata, DecryptionMaterials materials, byte[] ciphertext);
}
