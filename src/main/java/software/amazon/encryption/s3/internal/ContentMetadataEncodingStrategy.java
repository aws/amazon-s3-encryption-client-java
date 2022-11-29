package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Request;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

public interface ContentMetadataEncodingStrategy {

    CreateMultipartUploadRequest encodeMetadata(EncryptionMaterials materials,
                             byte[] nonce, CreateMultipartUploadRequest request);

    PutObjectRequest encodeMetadata(EncryptionMaterials materials,
                             byte[] nonce, PutObjectRequest request);
}
