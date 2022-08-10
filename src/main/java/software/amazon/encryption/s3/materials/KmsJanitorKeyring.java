package software.amazon.encryption.s3.materials;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.SecretKey;
import software.amazon.awssdk.core.ApiName;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.internal.ApiNameVersion;
import software.amazon.encryption.s3.materials.AesJanitorKeyring.Builder;

/**
 * KmsJanitorKeyring will encrypt with KMS and the encryption context and can handle legacy KMS decrypt.
 */
public class KmsJanitorKeyring extends S3JanitorKeyring {

    private static final ApiName API_NAME = ApiNameVersion.apiNameWithVersion();

    private final KmsClient _kmsClient;
    private final String _wrappingKeyId;

    private final DecryptDataKeyStrategy _kmsStrategy = new DecryptDataKeyStrategy() {

        private static final String KEY_PROVIDER_ID = "kms";

        @Override
        public boolean isLegacy() {
            return true;
        }

        @Override
        public String keyProviderId() {
            return KEY_PROVIDER_ID;
        }

        @Override
        public byte[] decryptDataKey(DecryptionMaterials materials, EncryptedDataKey encryptedDataKey) {
            DecryptRequest request = DecryptRequest.builder()
                    .keyId(_wrappingKeyId)
                    .encryptionContext(materials.encryptionContext())
                    .ciphertextBlob(SdkBytes.fromByteArray(encryptedDataKey.ciphertext()))
                    .overrideConfiguration(builder -> builder.addApiName(API_NAME))
                    .build();

            DecryptResponse response = _kmsClient.decrypt(request);
            return response.plaintext().asByteArray();
        }
    };

    private final DataKeyStrategy _kmsContextStrategy = new DataKeyStrategy() {

        private static final String KEY_PROVIDER_ID = "kms+context";
        private static final String ENCRYPTION_CONTEXT_ALGORITHM_KEY = "aws:x-amz-cek-alg";

        @Override
        public boolean isLegacy() {
            return false;
        }

        @Override
        public String keyProviderId() {
            return KEY_PROVIDER_ID;
        }

        @Override
        public byte[] encryptDataKey(SecureRandom secureRandom, EncryptionMaterials materials) {
            if (materials.encryptionContext().containsKey(ENCRYPTION_CONTEXT_ALGORITHM_KEY)) {
                throw new S3EncryptionClientException(ENCRYPTION_CONTEXT_ALGORITHM_KEY + " is a reserved key for the S3 encryption client");
            }

            TreeMap<String, String> encryptionContext = new TreeMap<>(materials.encryptionContext());
            encryptionContext.put(ENCRYPTION_CONTEXT_ALGORITHM_KEY, materials.algorithmSuite().cipherName());

            EncryptRequest request = EncryptRequest.builder()
                    .keyId(_wrappingKeyId)
                    .encryptionContext(encryptionContext)
                    .plaintext(SdkBytes.fromByteArray(materials.plaintextDataKey()))
                    .overrideConfiguration(builder -> builder.addApiName(API_NAME))
                    .build();

            EncryptResponse response = _kmsClient.encrypt(request);
            return response.ciphertextBlob().asByteArray();
        }

        @Override
        public byte[] decryptDataKey(DecryptionMaterials materials, EncryptedDataKey encryptedDataKey){
            DecryptRequest request = DecryptRequest.builder()
                    .keyId(_wrappingKeyId)
                    .encryptionContext(materials.encryptionContext())
                    .ciphertextBlob(SdkBytes.fromByteArray(encryptedDataKey.ciphertext()))
                    .overrideConfiguration(builder -> builder.addApiName(API_NAME))
                    .build();

            DecryptResponse response = _kmsClient.decrypt(request);
            return response.plaintext().asByteArray();
        }

    };

    private final Map<String, DecryptDataKeyStrategy> decryptStrategies = new HashMap<>();

    public KmsJanitorKeyring(Builder builder) {
        super(builder);

        _kmsClient = builder._kmsClient;
        _wrappingKeyId = builder._wrappingKeyId;

        decryptStrategies.put(_kmsStrategy.keyProviderId(), _kmsStrategy);
        decryptStrategies.put(_kmsContextStrategy.keyProviderId(), _kmsContextStrategy);
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    protected EncryptDataKeyStrategy encryptStrategy() {
        return _kmsContextStrategy;
    }

    @Override
    protected Map<String, DecryptDataKeyStrategy> decryptStrategies() {
        return decryptStrategies;
    }

    public static class Builder extends S3JanitorKeyring.Builder<KmsJanitorKeyring, Builder> {
        private KmsClient _kmsClient;
        private String _wrappingKeyId;

        private Builder() { super(); }

        @Override
        protected Builder builder() {
            return this;
        }

        public Builder kmsClient(KmsClient kmsClient) {
            _kmsClient = kmsClient;
            return this;
        }

        public Builder wrappingKeyId(String wrappingKeyId) {
            _wrappingKeyId = wrappingKeyId;
            return this;
        }

        public KmsJanitorKeyring build() {
            return new KmsJanitorKeyring(this);
        }
    }
}
