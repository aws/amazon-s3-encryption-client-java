package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

@FunctionalInterface
public interface ContentMetadataDecodingStrategy {
    ContentMetadata decodeMetadata(ResponseBytes<GetObjectResponse> instruction, GetObjectResponse response);
}
