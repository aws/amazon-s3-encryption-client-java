package software.amazon.encryption.s3.internal;

import java.util.Map;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

@FunctionalInterface
public interface ContentMetadataDecodingStrategy {
    ContentMetadata decodeMetadata(GetObjectResponse response);
}
