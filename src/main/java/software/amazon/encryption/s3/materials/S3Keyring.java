package software.amazon.encryption.s3.materials;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import software.amazon.encryption.s3.S3EncryptionClientException;

/**
 * This serves as the base class for all the keyrings in the S3 encryption client.
 * Shared functionality is all performed here.
 */
abstract public class S3Keyring implements Keyring {

    private final boolean _enableLegacyModes;
    private final SecureRandom _secureRandom;
    private final DataKeyGenerator _dataKeyGenerator;

    protected S3Keyring(Builder<?,?> builder) {
        _enableLegacyModes = builder._enableLegacyModes;
        _secureRandom = builder._secureRandom;
        _dataKeyGenerator = builder._dataKeyGenerator;
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials materials) {
        if (materials.plaintextDataKey() == null) {
            SecretKey dataKey = _dataKeyGenerator.generateDataKey(materials.algorithmSuite());
            materials = materials.toBuilder()
                    .plaintextDataKey(dataKey.getEncoded())
                    .build();
        }

        EncryptDataKeyStrategy encryptStrategy = encryptStrategy();
        try {
            // Allow encrypt strategy to modify the materials if necessary
            materials = encryptStrategy.modifyMaterials(materials);

            byte[] ciphertext = encryptStrategy.encryptDataKey(_secureRandom, materials);
            EncryptedDataKey encryptedDataKey = EncryptedDataKey.builder()
                    .keyProviderId(encryptStrategy.keyProviderId())
                    .ciphertext(ciphertext)
                    .build();

            List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>(materials.encryptedDataKeys());
            encryptedDataKeys.add(encryptedDataKey);

            return materials.toBuilder()
                    .encryptedDataKeys(encryptedDataKeys)
                    .build();
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to " + encryptStrategy.keyProviderId() + " wrap", e);
        }
    }

    abstract protected EncryptDataKeyStrategy encryptStrategy();

    @Override
    public DecryptionMaterials onDecrypt(final DecryptionMaterials materials, List<EncryptedDataKey> encryptedDataKeys) {
        if (materials.plaintextDataKey() != null) {
            throw new S3EncryptionClientException("Decryption materials already contains a plaintext data key.");
        }

        if (encryptedDataKeys.size() != 1) {
            throw new S3EncryptionClientException("Only one encrypted data key is supported, found: " + encryptedDataKeys.size());
        }

        EncryptedDataKey encryptedDataKey = encryptedDataKeys.get(0);
        final String keyProviderId = encryptedDataKey.keyProviderId();

        DecryptDataKeyStrategy decryptStrategy = decryptStrategies().get(keyProviderId);
        if (decryptStrategy == null) {
            throw new S3EncryptionClientException("Unknown key wrap: " + keyProviderId);
        }

        if (decryptStrategy.isLegacy() && !_enableLegacyModes) {
            throw new S3EncryptionClientException("Enable legacy modes to use legacy key wrap: " + keyProviderId);
        }

        try {
            byte[] plaintext = decryptStrategy.decryptDataKey(materials, encryptedDataKey);
            return materials.toBuilder().plaintextDataKey(plaintext).build();
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to " + keyProviderId + " unwrap", e);
        }
    }

    abstract protected Map<String,DecryptDataKeyStrategy> decryptStrategies();

    abstract public static class Builder<KeyringT extends S3Keyring, BuilderT extends Builder<KeyringT, BuilderT>> {
        private boolean _enableLegacyModes = false;
        private SecureRandom _secureRandom = new SecureRandom();
        private DataKeyGenerator _dataKeyGenerator = new DefaultDataKeyGenerator();


        protected Builder() {}

        protected abstract BuilderT builder();

        public BuilderT enableLegacyModes(boolean shouldEnableLegacyModes) {
            this._enableLegacyModes = shouldEnableLegacyModes;
            return builder();
        }

        public BuilderT secureRandom(SecureRandom secureRandom) {
            _secureRandom = secureRandom;
            return builder();
        }

        public BuilderT dataKeyGenerator(DataKeyGenerator dataKeyGenerator) {
            _dataKeyGenerator = dataKeyGenerator;
            return builder();
        }

        abstract public KeyringT build();
    }
}
