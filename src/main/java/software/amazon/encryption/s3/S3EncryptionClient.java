package software.amazon.encryption.s3;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.encryption.s3.internal.GetEncryptedObjectPipeline;
import software.amazon.encryption.s3.internal.PutEncryptedObjectPipeline;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;

public class S3EncryptionClient implements S3Client {

    private final S3Client _wrappedClient;
    private final CryptographicMaterialsManager _cryptoMaterialsManager;

    private S3EncryptionClient(Builder builder) {
        _wrappedClient = builder._wrappedClient;
        _cryptoMaterialsManager = builder._cryptoMaterialsManager;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public PutObjectResponse putObject(PutObjectRequest putObjectRequest, RequestBody requestBody)
            throws AwsServiceException, SdkClientException {

        PutEncryptedObjectPipeline pipeline = PutEncryptedObjectPipeline.builder()
                .s3Client(_wrappedClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .build();

        return pipeline.putObject(putObjectRequest, requestBody);
    }

    @Override
    public <T> T getObject(GetObjectRequest getObjectRequest,
            ResponseTransformer<GetObjectResponse, T> responseTransformer)
            throws AwsServiceException, SdkClientException {

        GetEncryptedObjectPipeline pipeline = GetEncryptedObjectPipeline.builder()
                .s3Client(_wrappedClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .build();

        return pipeline.getObject(getObjectRequest, responseTransformer);
    }

    @Override
    public String serviceName() {
        return _wrappedClient.serviceName();
    }

    @Override
    public void close() {
        _wrappedClient.close();
    }

    public static class Builder {
        private S3Client _wrappedClient = S3Client.builder().build();
        private CryptographicMaterialsManager _cryptoMaterialsManager;

        private Builder() {}

        public Builder wrappedClient(S3Client wrappedClient) {
            this._wrappedClient = wrappedClient;
            return this;
        }

        public Builder cryptoMaterialsManager(CryptographicMaterialsManager cryptoMaterialsManager) {
            this._cryptoMaterialsManager = cryptoMaterialsManager;
            return this;
        }

        public S3EncryptionClient build() {
            return new S3EncryptionClient(this);
        }
    }
}
