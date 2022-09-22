package software.amazon.encryption.s3;

import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.interceptor.ExecutionAttribute;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.encryption.s3.internal.GetEncryptedObjectPipeline;
import software.amazon.encryption.s3.internal.PutEncryptedObjectPipeline;
import software.amazon.encryption.s3.materials.*;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

/**
 * This client is a drop-in replacement for the S3 Async Client. It will automatically encrypt objects
 * on putObject and decrypt objects on getObject using the provided encryption key(s).
 */
public class S3AsyncEncryptionClient implements S3AsyncClient {

    // Used for request-scoped encryption contexts for supporting keys
    public static final ExecutionAttribute<Map<String,String>> ENCRYPTION_CONTEXT = new ExecutionAttribute<>("EncryptionContextAsync");

    private final S3AsyncClient _wrappedClient;
    private final CryptographicMaterialsManager _cryptoMaterialsManager;
    private final boolean _enableLegacyModes;

    private S3AsyncEncryptionClient(Builder builder) {
        _wrappedClient = builder._wrappedClient;
        _cryptoMaterialsManager = builder._cryptoMaterialsManager;
        _enableLegacyModes = builder._enableLegacyModes;
    }

    public static Builder builder() {
        return new Builder();
    }

    // Helper function to attach encryption contexts to a request
    public static Consumer<AwsRequestOverrideConfiguration.Builder> withAdditionalEncryptionContext(Map<String, String> encryptionContext) {
        return builder ->
                builder.putExecutionAttribute(S3AsyncEncryptionClient.ENCRYPTION_CONTEXT, encryptionContext);
    }

    @Override
    public CompletableFuture<PutObjectResponse> putObject(PutObjectRequest putObjectRequest, AsyncRequestBody asyncRequestBody) {
        PutEncryptedObjectPipeline pipeline = PutEncryptedObjectPipeline.builder()
                .s3AsyncClient(_wrappedClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .build();

        try {
            return pipeline.putObject(putObjectRequest, asyncRequestBody);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public <T> CompletableFuture<T> getObject(GetObjectRequest getObjectRequest,
                                                 AsyncResponseTransformer<GetObjectResponse, T> asyncResponseTransformer) {
        GetEncryptedObjectPipeline pipeline = GetEncryptedObjectPipeline.builder()
                .s3AsyncClient(_wrappedClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .enableLegacyModes(_enableLegacyModes)
                .build();

        try {
            return pipeline.getObject(getObjectRequest, asyncResponseTransformer);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
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
        private S3AsyncClient _wrappedClient = S3AsyncClient.builder().build();
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        private Keyring _keyring;
        private SecretKey _aesKey;
        private PartialRsaKeyPair _rsaKeyPair;
        private String _kmsKeyId;
        private boolean _enableLegacyModes = false;

        private Builder() {}

        public Builder wrappedClient(S3AsyncClient wrappedClient) {
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

        public Builder enableLegacyModes(boolean shouldEnableLegacyModes) {
            this._enableLegacyModes = shouldEnableLegacyModes;
            return this;
        }

        public S3AsyncEncryptionClient build() {
            if (!onlyOneNonNull(_cryptoMaterialsManager, _keyring, _aesKey, _rsaKeyPair, _kmsKeyId)) {
                throw new S3EncryptionClientException("Exactly one must be set of: crypto materials manager, keyring, AES key, RSA key pair, KMS key id");
            }

            if (_keyring == null) {
                if (_aesKey != null) {
                    _keyring = AesKeyring.builder()
                            .wrappingKey(_aesKey)
                            .enableLegacyModes(_enableLegacyModes)
                            .build();
                } else if (_rsaKeyPair != null) {
                    _keyring = RsaKeyring.builder()
                            .wrappingKeyPair(_rsaKeyPair)
                            .enableLegacyModes(_enableLegacyModes)
                            .build();
                } else if (_kmsKeyId != null) {
                    _keyring = KmsKeyring.builder()
                            .wrappingKeyId(_kmsKeyId)
                            .enableLegacyModes(_enableLegacyModes)
                            .build();
                }
            }

            if (_cryptoMaterialsManager == null) {
                _cryptoMaterialsManager = DefaultCryptoMaterialsManager.builder()
                        .keyring(_keyring)
                        .build();
            }

            return new S3AsyncEncryptionClient(this);
        }
    }
}
