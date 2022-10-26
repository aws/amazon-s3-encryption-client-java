package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.materials.DecryptionMaterials;

import java.io.InputStream;

@FunctionalInterface
public interface ContentDecryptionStrategy {
    InputStream decryptContent(ContentMetadata contentMetadata, DecryptionMaterials materials, InputStream ciphertext, String contentRange);
}
