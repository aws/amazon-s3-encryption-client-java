package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import java.util.concurrent.ExecutionException;

@FunctionalInterface
public interface ContentMetadataDecodingStrategyAsync {
    ContentMetadata decodeMetadata(S3AsyncClient client, GetObjectRequest request, GetObjectResponse response) throws ExecutionException, InterruptedException;
}
