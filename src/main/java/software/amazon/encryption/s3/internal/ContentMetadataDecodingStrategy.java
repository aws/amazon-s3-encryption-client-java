package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

@FunctionalInterface
public interface ContentMetadataDecodingStrategy {
    <T> ContentMetadata decodeMetadata(T client, GetObjectRequest request, GetObjectResponse response);
}
