package software.amazon.encryption.s3.materials;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

/**
 * This is the AES Janitor keyring because it can open many doors with one key
 */
public class AesJanitorKeyring implements Keyring {

    private static final String KEY_ALGORITHM = "AES";

    private static final DecryptDataKeyStrategy AES = new DecryptDataKeyStrategy() {
        @Override
        public boolean isLegacy() {
            return true;
        }

        @Override
        public String keyProviderId() {
            return "AES";
        }

        @Override
        public byte[] decryptDataKey(Key unwrappingKey, DecryptionMaterials materials, EncryptedDataKey encryptedDataKey) throws GeneralSecurityException {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, unwrappingKey);

            return cipher.doFinal(encryptedDataKey.ciphertext());
        }
    };

    private static final DecryptDataKeyStrategy AES_WRAP = new DecryptDataKeyStrategy() {
        @Override
        public boolean isLegacy() {
            return true;
        }

        @Override
        public String keyProviderId() {
            return "AESWrap";
        }

        @Override
        public byte[] decryptDataKey(Key unwrappingKey, DecryptionMaterials materials, EncryptedDataKey encryptedDataKey) throws GeneralSecurityException {
            final String cipherAlgorithm = "AESWrap";
            final Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(Cipher.UNWRAP_MODE, unwrappingKey);

            Key plaintextKey = cipher.unwrap(encryptedDataKey.ciphertext(), cipherAlgorithm, Cipher.SECRET_KEY);
            return plaintextKey.getEncoded();
        }
    };

    private static final String KEY_PROVIDER_ID = "AES/GCM";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int NONCE_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BYTES = 16;
    private static final int TAG_LENGTH_BITS = TAG_LENGTH_BYTES * 8;

    private static final DecryptDataKeyStrategy AES_GCM = new DecryptDataKeyStrategy() {
        @Override
        public boolean isLegacy() {
            return false;
        }

        @Override
        public String keyProviderId() {
            return "AES/GCM";
        }

        @Override
        public byte[] decryptDataKey(Key unwrappingKey, DecryptionMaterials materials, EncryptedDataKey encryptedDataKey) throws GeneralSecurityException {
            byte[] encodedBytes = encryptedDataKey.ciphertext();
            byte[] nonce = new byte[NONCE_LENGTH_BYTES];
            byte[] ciphertext = new byte[encodedBytes.length - nonce.length];

            System.arraycopy(encodedBytes, 0, nonce, 0, nonce.length);
            System.arraycopy(encodedBytes, nonce.length, ciphertext, 0, ciphertext.length);

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, nonce);
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, unwrappingKey, gcmParameterSpec);

            AlgorithmSuite algorithmSuite = materials.algorithmSuite();
            cipher.updateAAD(algorithmSuite.cipherName().getBytes(StandardCharsets.UTF_8));
            return cipher.doFinal(ciphertext);
        }
    };

    private static final Map<String, DecryptDataKeyStrategy> DECRYPT_STRATEGIES = new HashMap<>();
    static {
        DECRYPT_STRATEGIES.put(AES.keyProviderId(), AES);
        DECRYPT_STRATEGIES.put(AES_WRAP.keyProviderId(), AES_WRAP);
        DECRYPT_STRATEGIES.put(AES_GCM.keyProviderId(), AES_GCM);
    }

    private final SecretKey _wrappingKey;
    private final boolean _enableLegacyModes;
    private final SecureRandom _secureRandom;
    private final DataKeyGenerator _dataKeyGenerator;

    private AesJanitorKeyring(Builder builder) {
        _wrappingKey = builder._wrappingKey;
        _enableLegacyModes = builder._enableLegacyModes;
        _secureRandom = builder._secureRandom;
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

        try {
            byte[] nonce = new byte[NONCE_LENGTH_BYTES];
            _secureRandom.nextBytes(nonce);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, nonce);

            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, _wrappingKey, gcmParameterSpec, _secureRandom);

            AlgorithmSuite algorithmSuite = materials.algorithmSuite();
            cipher.updateAAD(algorithmSuite.cipherName().getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = cipher.doFinal(materials.plaintextDataKey());

            // The encrypted data key is the nonce prepended to the ciphertext
            byte[] encodedBytes = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, encodedBytes, 0, nonce.length);
            System.arraycopy(ciphertext, 0, encodedBytes, nonce.length, ciphertext.length);

            EncryptedDataKey encryptedDataKey = EncryptedDataKey.builder()
                    .keyProviderId(KEY_PROVIDER_ID)
                    .ciphertext(encodedBytes)
                    .build();

            List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>(materials.encryptedDataKeys());
            encryptedDataKeys.add(encryptedDataKey);

            return materials.toBuilder()
                    .encryptedDataKeys(encryptedDataKeys)
                    .build();
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to " + KEY_PROVIDER_ID + " wrap", e);
        }
    }

    @Override
    public DecryptionMaterials onDecrypt(final DecryptionMaterials materials, List<EncryptedDataKey> encryptedDataKeys) {
        if (materials.plaintextDataKey() != null) {
            throw new S3EncryptionClientException("Decryption materials already contains a plaintext data key.");
        }

        // TODO: error if more than one encrypted data key
        for (EncryptedDataKey encryptedDataKey : encryptedDataKeys) {
            final String keyProviderId = encryptedDataKey.keyProviderId();
            DecryptDataKeyStrategy decryptStrategy = DECRYPT_STRATEGIES.get(keyProviderId);
            if (decryptStrategy == null) {
                continue;
            }

            if (decryptStrategy.isLegacy() && !_enableLegacyModes) {
                throw new S3EncryptionClientException("Enable legacy modes to use legacy key wrap: " + keyProviderId);
            }

            try {
                byte[] plaintext = decryptStrategy.decryptDataKey(_wrappingKey, materials, encryptedDataKey);
                return materials.toBuilder().plaintextDataKey(plaintext).build();
            } catch (Exception e) {
                throw new S3EncryptionClientException("Unable to " + KEY_PROVIDER_ID + " unwrap", e);
            }
        }

        return materials;
    }

    public static class Builder {
        private SecretKey _wrappingKey;
        private boolean _enableLegacyModes = false;
        private SecureRandom _secureRandom = new SecureRandom();
        private DataKeyGenerator _dataKeyGenerator = new DefaultDataKeyGenerator();


        private Builder() {}

        public Builder wrappingKey(SecretKey wrappingKey) {
            if (!wrappingKey.getAlgorithm().equals(KEY_ALGORITHM)) {
                throw new S3EncryptionClientException("Invalid algorithm: " + wrappingKey.getAlgorithm() + ", expecting " + KEY_ALGORITHM);
            }
            _wrappingKey = wrappingKey;
            return this;
        }

        public Builder enableLegacyModes(boolean shouldEnableLegacyModes) {
            this._enableLegacyModes = shouldEnableLegacyModes;
            return this;
        }

        public Builder secureRandom(SecureRandom secureRandom) {
            _secureRandom = secureRandom;
            return this;
        }

        public Builder dataKeyGenerator(DataKeyGenerator dataKeyGenerator) {
            _dataKeyGenerator = dataKeyGenerator;
            return this;
        }

        public AesJanitorKeyring build() {
            return new AesJanitorKeyring(this);
        }
    }
}
