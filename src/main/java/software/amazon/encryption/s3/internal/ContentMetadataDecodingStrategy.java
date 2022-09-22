package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import java.util.concurrent.ExecutionException;

public interface ContentMetadataDecodingStrategy {
    ContentMetadata decodeMetadata(S3Client client, GetObjectRequest request, GetObjectResponse response);

    ContentMetadata decodeMetadataAsync(S3AsyncClient client, GetObjectRequest getObjectRequest, GetObjectResponse response) throws ExecutionException, InterruptedException;
}
