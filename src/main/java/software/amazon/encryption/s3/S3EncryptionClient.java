package software.amazon.encryption.s3;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.security.KeyPair;
import java.security.Provider;
import java.util.ArrayList;
import java.util.List;
import java.security.SecureRandom;
import java.util.Map;
import java.util.function.Consumer;
import javax.crypto.SecretKey;

import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.interceptor.ExecutionAttribute;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3Client;
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
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DefaultCryptoMaterialsManager;
import software.amazon.encryption.s3.materials.Keyring;
import software.amazon.encryption.s3.materials.KmsKeyring;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;
import software.amazon.encryption.s3.materials.RsaKeyring;

/**
 * This client is a drop-in replacement for the S3 client. It will automatically encrypt objects
 * on putObject and decrypt objects on getObject using the provided encryption key(s).
 */
public class S3EncryptionClient implements S3Client {

    // Used for request-scoped encryption contexts for supporting keys
    public static final ExecutionAttribute<Map<String, String>> ENCRYPTION_CONTEXT = new ExecutionAttribute<>("EncryptionContext");

    private final S3Client _wrappedClient;
    private final CryptographicMaterialsManager _cryptoMaterialsManager;
    private final SecureRandom _secureRandom;
    private final boolean _enableLegacyUnauthenticatedModes;
    private final boolean _enableDelayedAuthenticationMode;

    private S3EncryptionClient(Builder builder) {
        _wrappedClient = builder._wrappedClient;
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
    public PutObjectResponse putObject(PutObjectRequest putObjectRequest, RequestBody requestBody)
            throws AwsServiceException, SdkClientException {

        PutEncryptedObjectPipeline pipeline = PutEncryptedObjectPipeline.builder()
                .s3Client(_wrappedClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .secureRandom(_secureRandom)
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
                .enableLegacyUnauthenticatedModes(_enableLegacyUnauthenticatedModes)
                .enableDelayedAuthentication(_enableDelayedAuthenticationMode)
                .build();

        return pipeline.getObject(getObjectRequest, responseTransformer);
    }

    @Override
    public DeleteObjectResponse deleteObject(DeleteObjectRequest deleteObjectRequest) throws AwsServiceException,
            SdkClientException {
        // Delete the object
        DeleteObjectResponse deleteObjectResponse = _wrappedClient.deleteObject(deleteObjectRequest);
        // If Instruction file exists, delete the instruction file as well.
        String instructionObjectKey = deleteObjectRequest.key() + ".instruction";
        _wrappedClient.deleteObject(builder -> builder
                .bucket(deleteObjectRequest.bucket())
                .key(instructionObjectKey));
        return deleteObjectResponse;
    }

    @Override
    public DeleteObjectsResponse deleteObjects(DeleteObjectsRequest deleteObjectsRequest) throws AwsServiceException,
            SdkClientException {
        // Delete the objects
        DeleteObjectsResponse deleteObjectsResponse = _wrappedClient.deleteObjects(deleteObjectsRequest);
        // If Instruction files exists, delete the instruction files as well.
        List<ObjectIdentifier> deleteObjects = new ArrayList<>();
        for (ObjectIdentifier o : deleteObjectsRequest.delete().objects()) {
            deleteObjects.add(o.toBuilder()
                    .key(o.key() + ".instruction")
                    .build());
        }
        _wrappedClient.deleteObjects(DeleteObjectsRequest.builder()
                .bucket(deleteObjectsRequest.bucket())
                .delete(builder -> builder.objects(deleteObjects))
                .build());
        return deleteObjectsResponse;
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
        private SecretKey _aesKey;
        private PartialRsaKeyPair _rsaKeyPair;
        private String _kmsKeyId;
        private boolean _enableLegacyUnauthenticatedModes = false;
        private boolean _enableDelayedAuthenticationMode = false;
        private Provider _cryptoProvider = null;
        private SecureRandom _secureRandom = new SecureRandom();

        private Builder() {
        }

        /**
         * Note that this does NOT create a defensive clone of S3Client. Any modifications made to the wrapped
         * S3Client will be reflected in this Builder.
         */
        @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "Pass mutability into wrapping client")
        public Builder wrappedClient(S3Client wrappedClient) {
            if (wrappedClient instanceof S3EncryptionClient) {
                throw new S3EncryptionClientException("Cannot use S3EncryptionClient as wrapped client");
            }

            this._wrappedClient = wrappedClient;
            return this;
        }

        public Builder cryptoMaterialsManager(CryptographicMaterialsManager cryptoMaterialsManager) {
            this._cryptoMaterialsManager = cryptoMaterialsManager;
            checkKeyOptions();

            return this;
        }

        public Builder keyring(Keyring keyring) {
            this._keyring = keyring;
            checkKeyOptions();

            return this;
        }

        public Builder aesKey(SecretKey aesKey) {
            this._aesKey = aesKey;
            checkKeyOptions();

            return this;
        }

        public Builder rsaKeyPair(KeyPair rsaKeyPair) {
            this._rsaKeyPair = new PartialRsaKeyPair(rsaKeyPair);
            checkKeyOptions();

            return this;
        }

        public Builder rsaKeyPair(PartialRsaKeyPair partialRsaKeyPair) {
            this._rsaKeyPair = partialRsaKeyPair;
            checkKeyOptions();

            return this;
        }

        public Builder kmsKeyId(String kmsKeyId) {
            this._kmsKeyId = kmsKeyId;
            checkKeyOptions();

            return this;
        }

        // We only want one way to use a key, if more than one is set, throw an error
        private void checkKeyOptions() {
            if (onlyOneNonNull(_cryptoMaterialsManager, _keyring, _aesKey, _rsaKeyPair, _kmsKeyId)) {
                return;
            }

            throw new S3EncryptionClientException("Only one may be set of: crypto materials manager, keyring, AES key, RSA key pair, KMS key id");
        }

        private boolean onlyOneNonNull(Object... values) {
            boolean haveOneNonNull = false;
            for (Object o : values) {
                if (o != null) {
                    if (haveOneNonNull) {
                        return false;
                    }

                    haveOneNonNull = true;
                }
            }

            return haveOneNonNull;
        }

        public Builder enableLegacyUnauthenticatedModes(boolean shouldEnableLegacyUnauthenticatedModes) {
            this._enableLegacyUnauthenticatedModes = shouldEnableLegacyUnauthenticatedModes;
            return this;
        }

        public Builder enableDelayedAuthenticationMode(boolean shouldEnableDelayedAuthenticationMode) {
            this._enableDelayedAuthenticationMode = shouldEnableDelayedAuthenticationMode;
            return this;
        }

        public Builder cryptoProvider(Provider cryptoProvider) {
            this._cryptoProvider = cryptoProvider;
            return this;
        }
           
        public Builder secureRandom(SecureRandom secureRandom) {
            if (secureRandom == null) {
                throw new S3EncryptionClientException("SecureRandom provided to S3EncryptionClient cannot be null");
            }
            _secureRandom = secureRandom;
            return this;
        }

        public S3EncryptionClient build() {
            if (!onlyOneNonNull(_cryptoMaterialsManager, _keyring, _aesKey, _rsaKeyPair, _kmsKeyId)) {
                throw new S3EncryptionClientException("Exactly one must be set of: crypto materials manager, keyring, AES key, RSA key pair, KMS key id");
            }

            if (_keyring == null) {
                if (_aesKey != null) {
                    _keyring = AesKeyring.builder()
                            .wrappingKey(_aesKey)
                            .enableLegacyUnauthenticatedModes(_enableLegacyUnauthenticatedModes)
                            .secureRandom(_secureRandom)
                            .build();
                } else if (_rsaKeyPair != null) {
                    _keyring = RsaKeyring.builder()
                            .wrappingKeyPair(_rsaKeyPair)
                            .enableLegacyUnauthenticatedModes(_enableLegacyUnauthenticatedModes)
                            .secureRandom(_secureRandom)
                            .build();
                } else if (_kmsKeyId != null) {
                    _keyring = KmsKeyring.builder()
                            .wrappingKeyId(_kmsKeyId)
                            .enableLegacyUnauthenticatedModes(_enableLegacyUnauthenticatedModes)
                            .secureRandom(_secureRandom)
                            .build();
                }
            }

            if (_cryptoMaterialsManager == null) {
                _cryptoMaterialsManager = DefaultCryptoMaterialsManager.builder()
                        .keyring(_keyring)
                        .cryptoProvider(_cryptoProvider)
                        .build();
            }

            return new S3EncryptionClient(this);
        }
    }
}
