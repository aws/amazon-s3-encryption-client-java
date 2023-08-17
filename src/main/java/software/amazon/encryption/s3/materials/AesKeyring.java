// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.CryptoFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

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
        public boolean isLegacy() {
            return true;
        }

        @Override
        public String keyProviderInfo() {
            return KEY_PROVIDER_INFO;
        }

        @Override
        public byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey) throws GeneralSecurityException {
            final Cipher cipher = CryptoFactory.createCipher(CIPHER_ALGORITHM, materials.cryptoProvider());
            cipher.init(Cipher.DECRYPT_MODE, _wrappingKey);

            return cipher.doFinal(encryptedDataKey);
        }
    };

    private final DecryptDataKeyStrategy _aesWrapStrategy = new DecryptDataKeyStrategy() {

        private static final String KEY_PROVIDER_INFO = "AESWrap";
        private static final String CIPHER_ALGORITHM = "AESWrap";

        @Override
        public boolean isLegacy() {
            return true;
        }

        @Override
        public String keyProviderInfo() {
            return KEY_PROVIDER_INFO;
        }

        @Override
        public byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey) throws GeneralSecurityException {
            final Cipher cipher = CryptoFactory.createCipher(CIPHER_ALGORITHM, materials.cryptoProvider());
            cipher.init(Cipher.UNWRAP_MODE, _wrappingKey);

            Key plaintextKey = cipher.unwrap(encryptedDataKey, CIPHER_ALGORITHM, Cipher.SECRET_KEY);
            return plaintextKey.getEncoded();
        }
    };

    private final DataKeyStrategy _aesGcmStrategy = new DataKeyStrategy() {

        private static final String KEY_PROVIDER_INFO = "AES/GCM";
        private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
        private static final int IV_LENGTH_BYTES = 12;
        private static final int TAG_LENGTH_BYTES = 16;
        private static final int TAG_LENGTH_BITS = TAG_LENGTH_BYTES * 8;

        @Override
        public boolean isLegacy() {
            return false;
        }

        @Override
        public String keyProviderInfo() {
            return KEY_PROVIDER_INFO;
        }

        @Override
        public EncryptionMaterials generateDataKey(EncryptionMaterials materials) {
            return defaultGenerateDataKey(materials);
        }

        @Override
        public EncryptionMaterials modifyMaterials(EncryptionMaterials materials) {
            warnIfEncryptionContextIsPresent(materials);

            return materials;
        }

        @Override
        public byte[] encryptDataKey(SecureRandom secureRandom,
                EncryptionMaterials materials)
                throws GeneralSecurityException {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);

            final Cipher cipher = CryptoFactory.createCipher(CIPHER_ALGORITHM, materials.cryptoProvider());
            cipher.init(Cipher.ENCRYPT_MODE, _wrappingKey, gcmParameterSpec, secureRandom);

            final byte[] aADBytes = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherName().getBytes(StandardCharsets.UTF_8);
            cipher.updateAAD(aADBytes);
            byte[] ciphertext = cipher.doFinal(materials.plaintextDataKey());

            // The encrypted data key is the iv prepended to the ciphertext
            byte[] encodedBytes = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, encodedBytes, 0, iv.length);
            System.arraycopy(ciphertext, 0, encodedBytes, iv.length, ciphertext.length);

            return encodedBytes;
        }

        @Override
        public byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey) throws GeneralSecurityException {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            byte[] ciphertext = new byte[encryptedDataKey.length - iv.length];

            System.arraycopy(encryptedDataKey, 0, iv, 0, iv.length);
            System.arraycopy(encryptedDataKey, iv.length, ciphertext, 0, ciphertext.length);

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            final Cipher cipher = CryptoFactory.createCipher(CIPHER_ALGORITHM, materials.cryptoProvider());
            cipher.init(Cipher.DECRYPT_MODE, _wrappingKey, gcmParameterSpec);

            final byte[] aADBytes = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherName().getBytes(StandardCharsets.UTF_8);
            cipher.updateAAD(aADBytes);
            return cipher.doFinal(ciphertext);
        }
    };

    private final Map<String, DecryptDataKeyStrategy> decryptDataKeyStrategies = new HashMap<>();

    private AesKeyring(Builder builder) {
        super(builder);

        _wrappingKey = builder._wrappingKey;

        decryptDataKeyStrategies.put(_aesStrategy.keyProviderInfo(), _aesStrategy);
        decryptDataKeyStrategies.put(_aesWrapStrategy.keyProviderInfo(), _aesWrapStrategy);
        decryptDataKeyStrategies.put(_aesGcmStrategy.keyProviderInfo(), _aesGcmStrategy);
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    protected GenerateDataKeyStrategy generateDataKeyStrategy() {
        return _aesGcmStrategy;
    }

    @Override
    protected EncryptDataKeyStrategy encryptDataKeyStrategy() {
        return _aesGcmStrategy;
    }

    @Override
    protected Map<String, DecryptDataKeyStrategy> decryptDataKeyStrategies() {
        return decryptDataKeyStrategies;
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
