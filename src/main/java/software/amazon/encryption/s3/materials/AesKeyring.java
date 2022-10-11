package software.amazon.encryption.s3.materials;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

/**
 * This keyring can wrap keys with the active keywrap algorithm and
 * unwrap with the active and legacy algorithms for AES keys.
 */
public class AesKeyring extends S3Keyring {

    private static final String KEY_ALGORITHM = "AES";

    private final SecretKey _wrappingKey;

    private final DecryptDataKeyStrategy _aesStrategy = new DecryptDataKeyStrategy() {

        private static final String KEY_PROVIDER_INFO = "AES";
        private static final String CIPHER_ALGORITHM = "AES";

        @Override
        public boolean isLegacyUnauthenticated() {
            return true;
        }

        @Override
        public String keyProviderInfo() {
            return KEY_PROVIDER_INFO;
        }

        @Override
        public byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey) throws GeneralSecurityException {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, _wrappingKey);

            return cipher.doFinal(encryptedDataKey);
        }
    };

    private final DecryptDataKeyStrategy _aesWrapStrategy = new DecryptDataKeyStrategy() {

        private static final String KEY_PROVIDER_INFO = "AESWrap";
        private static final String CIPHER_ALGORITHM = "AESWrap";

        @Override
        public boolean isLegacyUnauthenticated() {
            return true;
        }

        @Override
        public String keyProviderInfo() {
            return KEY_PROVIDER_INFO;
        }

        @Override
        public byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey) throws GeneralSecurityException {
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.UNWRAP_MODE, _wrappingKey);

            Key plaintextKey = cipher.unwrap(encryptedDataKey, CIPHER_ALGORITHM, Cipher.SECRET_KEY);
            return plaintextKey.getEncoded();
        }
    };

    private final DataKeyStrategy _aesGcmStrategy = new DataKeyStrategy() {

        private static final String KEY_PROVIDER_INFO = "AES/GCM";
        private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
        private static final int NONCE_LENGTH_BYTES = 12;
        private static final int TAG_LENGTH_BYTES = 16;
        private static final int TAG_LENGTH_BITS = TAG_LENGTH_BYTES * 8;

        @Override
        public boolean isLegacyUnauthenticated() {
            return false;
        }

        @Override
        public String keyProviderInfo() {
            return KEY_PROVIDER_INFO;
        }

        @Override
        public byte[] encryptDataKey(SecureRandom secureRandom,
                EncryptionMaterials materials)
                throws GeneralSecurityException {
            byte[] nonce = new byte[NONCE_LENGTH_BYTES];
            secureRandom.nextBytes(nonce);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, nonce);

            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, _wrappingKey, gcmParameterSpec, secureRandom);

            AlgorithmSuite algorithmSuite = materials.algorithmSuite();
            cipher.updateAAD(algorithmSuite.cipherName().getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = cipher.doFinal(materials.plaintextDataKey());

            // The encrypted data key is the nonce prepended to the ciphertext
            byte[] encodedBytes = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, encodedBytes, 0, nonce.length);
            System.arraycopy(ciphertext, 0, encodedBytes, nonce.length, ciphertext.length);

            return encodedBytes;
        }

        @Override
        public byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey) throws GeneralSecurityException {
            byte[] encodedBytes = encryptedDataKey;
            byte[] nonce = new byte[NONCE_LENGTH_BYTES];
            byte[] ciphertext = new byte[encodedBytes.length - nonce.length];

            System.arraycopy(encodedBytes, 0, nonce, 0, nonce.length);
            System.arraycopy(encodedBytes, nonce.length, ciphertext, 0, ciphertext.length);

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, nonce);
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, _wrappingKey, gcmParameterSpec);

            AlgorithmSuite algorithmSuite = materials.algorithmSuite();
            cipher.updateAAD(algorithmSuite.cipherName().getBytes(StandardCharsets.UTF_8));
            return cipher.doFinal(ciphertext);
        }
    };

    private final Map<String, DecryptDataKeyStrategy> decryptStrategies = new HashMap<>();

    private AesKeyring(Builder builder) {
        super(builder);

        _wrappingKey = builder._wrappingKey;

        decryptStrategies.put(_aesStrategy.keyProviderInfo(), _aesStrategy);
        decryptStrategies.put(_aesWrapStrategy.keyProviderInfo(), _aesWrapStrategy);
        decryptStrategies.put(_aesGcmStrategy.keyProviderInfo(), _aesGcmStrategy);
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    protected EncryptDataKeyStrategy encryptStrategy() {
        return _aesGcmStrategy;
    }

    @Override
    protected Map<String, DecryptDataKeyStrategy> decryptStrategies() {
        return decryptStrategies;
    }

    public static class Builder extends S3Keyring.Builder<AesKeyring, Builder> {
        private SecretKey _wrappingKey;

        private Builder() {
            super();
        }

        @Override
        protected Builder builder() {
            return this;
        }

        public Builder wrappingKey(final SecretKey wrappingKey) {
            if (wrappingKey == null) {
                throw new S3EncryptionClientException("Wrapping key cannot be null!");
            }
            if (!wrappingKey.getAlgorithm().equals(KEY_ALGORITHM)) {
                throw new S3EncryptionClientException("Invalid algorithm: " + wrappingKey.getAlgorithm() + ", expecting " + KEY_ALGORITHM);
            }
            _wrappingKey = wrappingKey;
            return builder();
        }

        public AesKeyring build() {
            return new AesKeyring(this);
        }
    }
}
