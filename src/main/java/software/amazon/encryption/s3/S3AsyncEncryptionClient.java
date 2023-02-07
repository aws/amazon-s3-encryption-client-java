package software.amazon.encryption.s3;

import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.encryption.s3.internal.GetEncryptedObjectPipeline;
import software.amazon.encryption.s3.internal.PutEncryptedObjectPipeline;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;

import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Function;

public class S3AsyncEncryptionClient implements S3AsyncClient {

    private final S3AsyncClient _wrappedClient;
    private final CryptographicMaterialsManager _cryptoMaterialsManager;
    private final SecureRandom _secureRandom;
    private final boolean _enableLegacyUnauthenticatedModes;
    private final boolean _enableDelayedAuthenticationMode;

    private S3AsyncEncryptionClient(Builder builder) {
        _wrappedClient = builder._wrappedAsyncClient;
        _cryptoMaterialsManager = builder._cryptoMaterialsManager;
        _secureRandom = builder._secureRandom;
        _enableLegacyUnauthenticatedModes = builder._enableLegacyUnauthenticatedModes;
        _enableDelayedAuthenticationMode = builder._enableDelayedAuthenticationMode;
    }

    public static Builder builder() {
        return new Builder();
    }

    // Helper function to attach encryption contexts to a request
    public static Consumer<AwsRequestOverrideConfiguration.Builder> withAdditionalEncryptionContext(Map<String, String> encryptionContext) {
        return builder ->
                builder.putExecutionAttribute(S3EncryptionClient.ENCRYPTION_CONTEXT, encryptionContext);
    }

    @Override
    public CompletableFuture<PutObjectResponse> putObject(PutObjectRequest putObjectRequest, AsyncRequestBody requestBody)
            throws AwsServiceException, SdkClientException {
        PutEncryptedObjectPipeline pipeline = PutEncryptedObjectPipeline.builder()
                .s3AsyncClient(_wrappedClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .secureRandom(_secureRandom)
                .build();

        return pipeline.putObject(putObjectRequest, requestBody);
    }

    @Override
    public <T> CompletableFuture<T> getObject(GetObjectRequest getObjectRequest,
                                              AsyncResponseTransformer<GetObjectResponse, T> asyncResponseTransformer) {
        GetEncryptedObjectPipeline pipeline = GetEncryptedObjectPipeline.builder()
                .s3AsyncClient(_wrappedClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .enableLegacyUnauthenticatedModes(_enableLegacyUnauthenticatedModes)
                .enableDelayedAuthentication(_enableDelayedAuthenticationMode)
                .build();

        return pipeline.getObject(getObjectRequest, asyncResponseTransformer);
    }

    @Override
    public CompletableFuture<DeleteObjectResponse> deleteObject(DeleteObjectRequest deleteObjectRequest) {
        // TODO: Pass-through requests MUST set the user agent
        final CompletableFuture<DeleteObjectResponse> response = _wrappedClient.deleteObject(deleteObjectRequest);
        final String instructionObjectKey = deleteObjectRequest.key() + ".instruction";
        final CompletableFuture<DeleteObjectResponse> instructionResponse =  _wrappedClient.deleteObject(builder -> builder
                .bucket(deleteObjectRequest.bucket())
                .key(instructionObjectKey));
        // Delete the instruction file, then delete the object
        Function<DeleteObjectResponse, DeleteObjectResponse> deletion = deleteObjectResponse ->
                response.join();
        return instructionResponse.thenApplyAsync(deletion);
    }

    @Override
    public CompletableFuture<DeleteObjectsResponse> deleteObjects(DeleteObjectsRequest deleteObjectsRequest) throws AwsServiceException,
            SdkClientException {
        // TODO: Pass-through requests MUST set the user agent
        // Add the instruction file keys to the list of objects to delete
        final List<ObjectIdentifier> objectsToDelete = S3EncryptionClientUtilities.instructionFileKeysToDelete(deleteObjectsRequest);
        // Add the original objects
        objectsToDelete.addAll(deleteObjectsRequest.delete().objects());
        return _wrappedClient.deleteObjects(deleteObjectsRequest.toBuilder()
                .delete(builder -> builder.objects(objectsToDelete))
                .build());
    }

    @Override
    public String serviceName() {
        return _wrappedClient.serviceName();
    }

    @Override
    public void close() {
        _wrappedClient.close();
    }

    // TODO: The async / non-async clients can probably share a builder - revisit after implementing async
    public static class Builder extends S3ClientBuilder{

        private Builder() {
            super();
        }

        @Override
        public S3AsyncEncryptionClient build() {
            _cryptoMaterialsManager = S3EncryptionClientUtilities.buildCMM(this);

            return new S3AsyncEncryptionClient(this);
        }
    }
}
