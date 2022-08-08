package software.amazon.encryption.s3.legacy.materials;

import java.util.List;
import software.amazon.awssdk.core.ApiName;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.internal.ApiNameVersion;
import software.amazon.encryption.s3.materials.*;

/**
 * KmsKeyring is a legacy, decrypt-only keyring and will use a KMS Master key to unwrap the data key
 * used to encrypt content.
 */
public class KmsKeyring implements Keyring {

    private static final String KEY_PROVIDER_ID = "kms";

    private static final ApiName API_NAME = ApiNameVersion.apiNameWithVersion();

    private final KmsClient _kmsClient;
    private final String _wrappingKeyId;
    private final DataKeyGenerator _dataKeyGenerator;

    public KmsKeyring(Builder builder) {
        _kmsClient = builder._kmsClient;
        _wrappingKeyId = builder._wrappingKeyId;
        _dataKeyGenerator = builder._dataKeyGenerator;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials materials) {
        throw new S3EncryptionClientException("Encrypt not supported for " + KEY_PROVIDER_ID);
    }

    @Override
    public DecryptionMaterials onDecrypt(final DecryptionMaterials materials, List<EncryptedDataKey> encryptedDataKeys) {
        if (materials.plaintextDataKey() != null) {
            throw new S3EncryptionClientException("Decryption materials already contains a plaintext data key.");
        }

        for (EncryptedDataKey encryptedDataKey : encryptedDataKeys) {
            if (!encryptedDataKey.keyProviderId().equals(KEY_PROVIDER_ID)) {
                continue;
            }

            try {
                DecryptRequest request = DecryptRequest.builder()
                        .keyId(_wrappingKeyId)
                        .encryptionContext(materials.encryptionContext())
                        .ciphertextBlob(SdkBytes.fromByteArray(encryptedDataKey.ciphertext()))
                        .overrideConfiguration(builder -> builder.addApiName(API_NAME))
                        .build();

                DecryptResponse response = _kmsClient.decrypt(request);

                return materials.toBuilder().plaintextDataKey(response.plaintext().asByteArray()).build();
            } catch (Exception e) {
                throw new S3EncryptionClientException("Unable to " + KEY_PROVIDER_ID + " unwrap", e);
            }
        }

        return materials;
    }

    public static class Builder {
        private KmsClient _kmsClient;
        private String _wrappingKeyId;
        private DataKeyGenerator _dataKeyGenerator = new DefaultDataKeyGenerator();

        private Builder() {}

        public Builder kmsClient(KmsClient kmsClient) {
            _kmsClient = kmsClient;
            return this;
        }

        public Builder wrappingKeyId(String wrappingKeyId) {
            _wrappingKeyId = wrappingKeyId;
            return this;
        }

        public Builder dataKeyGenerator(DataKeyGenerator dataKeyGenerator) {
            _dataKeyGenerator = dataKeyGenerator;
            return this;
        }

        public KmsKeyring build() {
            return new KmsKeyring(this);
        }
    }
}
