package software.amazon.encryption.s3.materials;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import javax.crypto.SecretKey;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.encryption.s3.S3EncryptionClientException;

/**
 * AESKeyring will call to KMS to wrap the data key used to encrypt content.
 */
public class KMSContextKeyring implements Keyring {

    private static final String KEY_PROVIDER_ID = "kms+context";

    private static final String ENCRYPTION_CONTEXT_ALGORITHM_KEY = "aws:x-amz-cek-alg";

    private final KmsClient _kmsClient;
    private final String _wrappingKeyId;
    private final DataKeyGenerator _dataKeyGenerator;

    public KMSContextKeyring(Builder builder) {
        _kmsClient = builder._kmsClient;
        _wrappingKeyId = builder._wrappingKeyId;
        _dataKeyGenerator = builder._dataKeyGenerator;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials materials) {
        if (materials.plaintextDataKey() == null) {
            SecretKey dataKey = _dataKeyGenerator.generateDataKey(materials.algorithmSuite());
            materials = materials.toBuilder()
                    .plaintextDataKey(dataKey.getEncoded())
                    .build();
        }

        if (materials.encryptionContext().containsKey(ENCRYPTION_CONTEXT_ALGORITHM_KEY)) {
            throw new S3EncryptionClientException(ENCRYPTION_CONTEXT_ALGORITHM_KEY + " is a reserved key for the S3 encryption client");
        }

        TreeMap<String, String> encryptionContext = new TreeMap<>(materials.encryptionContext());
        encryptionContext.put(ENCRYPTION_CONTEXT_ALGORITHM_KEY, materials.algorithmSuite().cipherName());

        try {
            EncryptRequest request = EncryptRequest.builder()
                    .keyId(_wrappingKeyId)
                    .encryptionContext(encryptionContext)
                    .plaintext(SdkBytes.fromByteArray(materials.plaintextDataKey()))
                    .build();

            EncryptResponse response = _kmsClient.encrypt(request);
            byte[] ciphertext = response.ciphertextBlob().asByteArray();

            EncryptedDataKey encryptedDataKey = EncryptedDataKey.builder()
                    .keyProviderId(KEY_PROVIDER_ID)
                    .ciphertext(ciphertext)
                    .build();

            List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>(materials.encryptedDataKeys());
            encryptedDataKeys.add(encryptedDataKey);

            return materials.toBuilder()
                    .encryptionContext(encryptionContext)
                    .encryptedDataKeys(encryptedDataKeys)
                    .build();
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to " + KEY_PROVIDER_ID + " wrap", e);
        }
    }

    @Override
    public DecryptionMaterials onDecrypt(final DecryptionMaterials materials, List<EncryptedDataKey> encryptedDataKeys) {
        if (materials.plaintextDataKey() != null) {
            return materials;
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

        public KMSContextKeyring build() {
            return new KMSContextKeyring(this);
        }
    }
}
