package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

@FunctionalInterface
public interface ContentMetadataEncodingStrategy {

    PutObjectRequest encodeMetadata(EncryptionMaterials materials,
            EncryptedContent encryptedContent, PutObjectRequest request);
}
