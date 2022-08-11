package software.amazon.encryption.s3.materials;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import software.amazon.awssdk.core.ApiName;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.internal.ApiNameVersion;

/**
 * This keyring can wrap keys with the active keywrap algorithm and
 * unwrap with the active and legacy algorithms for KMS keys.
 */
public class KmsKeyring extends S3Keyring {

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
        public EncryptionMaterials modifyMaterials(EncryptionMaterials materials) {
            if (materials.encryptionContext().containsKey(ENCRYPTION_CONTEXT_ALGORITHM_KEY)) {
                throw new S3EncryptionClientException(ENCRYPTION_CONTEXT_ALGORITHM_KEY + " is a reserved key for the S3 encryption client");
            }

            Map<String, String> encryptionContext = new HashMap<>(materials.encryptionContext());
            encryptionContext.put(ENCRYPTION_CONTEXT_ALGORITHM_KEY, materials.algorithmSuite().cipherName());

            return materials.toBuilder()
                    .encryptionContext(encryptionContext)
                    .build();
        }

        @Override
        public byte[] encryptDataKey(SecureRandom secureRandom, EncryptionMaterials materials) {
            // Convert to TreeMap for sorting of keys
            TreeMap<String, String> encryptionContext = new TreeMap<>(materials.encryptionContext());
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

    public KmsKeyring(Builder builder) {
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

    public static class Builder extends S3Keyring.Builder<KmsKeyring, Builder> {
        private KmsClient _kmsClient = KmsClient.builder().build();
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

        public KmsKeyring build() {
            return new KmsKeyring(this);
        }
    }
}
