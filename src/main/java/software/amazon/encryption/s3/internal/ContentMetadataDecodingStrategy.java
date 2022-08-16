package software.amazon.encryption.s3.internal;

import java.util.Map;

@FunctionalInterface
public interface ContentMetadataDecodingStrategy {
    ContentMetadata decodeMetadata(Map<String, String> response);
}
