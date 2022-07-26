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
import software.amazon.encryption.s3.legacy.materials.LegacyDecryptCryptoMaterialsManager;
import software.amazon.encryption.s3.legacy.materials.LegacyKeyring;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DecryptMaterialsRequest;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.DefaultCryptoMaterialsManager;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.Keyring;

public class S3EncryptionClient implements S3Client {

    private final S3Client _wrappedClient;
    private final CryptographicMaterialsManager _cryptoMaterialsManager;

    private S3EncryptionClient(Builder builder) {
        _wrappedClient = builder._wrappedClient;
        _cryptoMaterialsManager = builder._cryptoMaterialsManager;
        // TODO: store _enableLegacyModes and pass onto pipeline
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
        private Keyring _keyring;
        private boolean _enableLegacyModes = false;

        private Builder() {}

        public Builder wrappedClient(S3Client wrappedClient) {
            this._wrappedClient = wrappedClient;
            return this;
        }

        public Builder keyring(Keyring keyring) {
            this._keyring = keyring;
            return this;
        }

        public Builder cryptoMaterialsManager(CryptographicMaterialsManager cryptoMaterialsManager) {
            this._cryptoMaterialsManager = cryptoMaterialsManager;
            return this;
        }

        public Builder enableLegacyModes(boolean shouldEnableLegacyModes) {
            this._enableLegacyModes = shouldEnableLegacyModes;
            return this;
        }

        public S3EncryptionClient build() {
            if (_keyring != null && _cryptoMaterialsManager != null) {
                throw new S3EncryptionClientException("Only one of: a keyring or a crypto materials manager can be supplied");
            }

            if (_keyring != null) {
                if (_keyring instanceof LegacyKeyring) {
                    throw new S3EncryptionClientException("Configure manually a crypto materials manager when using a legacy keyring");
                }

                this._cryptoMaterialsManager = DefaultCryptoMaterialsManager.builder()
                        .keyring(_keyring)
                        .build();
            }

            if (!_enableLegacyModes && _cryptoMaterialsManager instanceof LegacyDecryptCryptoMaterialsManager) {
                throw new S3EncryptionClientException("Enable legacy modes to use a legacy crypto materials manager");
            }

            return new S3EncryptionClient(this);
        }
    }
}
