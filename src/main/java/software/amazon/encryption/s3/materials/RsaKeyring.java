// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.internal.CryptoFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * This keyring can wrap keys with the active keywrap algorithm and
 * unwrap with the active and legacy algorithms for RSA keys.
 */
public class RsaKeyring extends S3Keyring {

    private final PartialRsaKeyPair _partialRsaKeyPair;

    // Used exclusively by v1's EncryptionOnly mode
    private final DecryptDataKeyStrategy _rsaStrategy = new DecryptDataKeyStrategy() {
        private static final String KEY_PROVIDER_INFO = "RSA";
        private static final String CIPHER_ALGORITHM = "RSA";

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
            cipher.init(Cipher.DECRYPT_MODE, _partialRsaKeyPair.getPrivateKey());

            return cipher.doFinal(encryptedDataKey);
        }
    };

    private final DecryptDataKeyStrategy _rsaEcbStrategy = new DecryptDataKeyStrategy() {
        private static final String KEY_PROVIDER_INFO = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        private static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

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
            cipher.init(Cipher.UNWRAP_MODE, _partialRsaKeyPair.getPrivateKey());

            Key plaintextKey = cipher.unwrap(encryptedDataKey, CIPHER_ALGORITHM, Cipher.SECRET_KEY);

            return plaintextKey.getEncoded();
        }
    };

    private final DataKeyStrategy _rsaOaepStrategy = new DataKeyStrategy() {

        private static final String KEY_PROVIDER_INFO = "RSA-OAEP-SHA1";
        private static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPPadding";
        private static final String DIGEST_NAME = "SHA-1";
        private static final String MGF_NAME = "MGF1";

        // Java 8 doesn't support static class fields in inner classes
        private final MGF1ParameterSpec MGF_PARAMETER_SPEC = new MGF1ParameterSpec(DIGEST_NAME);
        private final OAEPParameterSpec OAEP_PARAMETER_SPEC =
                new OAEPParameterSpec(DIGEST_NAME, MGF_NAME, MGF_PARAMETER_SPEC, PSpecified.DEFAULT);

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
                                     EncryptionMaterials materials) throws GeneralSecurityException {
            final Cipher cipher = CryptoFactory.createCipher(CIPHER_ALGORITHM, materials.cryptoProvider());
            cipher.init(Cipher.WRAP_MODE, _partialRsaKeyPair.getPublicKey(), OAEP_PARAMETER_SPEC, secureRandom);

            // Create a pseudo-data key with the content encryption appended to the data key
            byte[] dataKey = materials.plaintextDataKey();
            byte[] dataCipherName = materials.algorithmSuite().cipherName().getBytes(
                    StandardCharsets.UTF_8);
            byte[] pseudoDataKey = new byte[1 + dataKey.length + dataCipherName.length];

            pseudoDataKey[0] = (byte)dataKey.length;
            System.arraycopy(dataKey, 0, pseudoDataKey, 1, dataKey.length);
            System.arraycopy(dataCipherName, 0, pseudoDataKey, 1 + dataKey.length, dataCipherName.length);

            byte[] ciphertext = cipher.wrap(new SecretKeySpec(pseudoDataKey, materials.algorithmSuite().dataKeyAlgorithm()));
            return ciphertext;
        }

        @Override
        public byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey) throws GeneralSecurityException {
            final Cipher cipher = CryptoFactory.createCipher(CIPHER_ALGORITHM, materials.cryptoProvider());
            cipher.init(Cipher.UNWRAP_MODE, _partialRsaKeyPair.getPrivateKey(), OAEP_PARAMETER_SPEC);

            String dataKeyAlgorithm = materials.algorithmSuite().dataKeyAlgorithm();
            Key pseudoDataKey = cipher.unwrap(encryptedDataKey, dataKeyAlgorithm, Cipher.SECRET_KEY);

            return parsePseudoDataKey(materials, pseudoDataKey.getEncoded());
        }

        private byte[] parsePseudoDataKey(DecryptionMaterials materials, byte[] pseudoDataKey) {
            int dataKeyLengthBytes = pseudoDataKey[0];
            if (!(dataKeyLengthBytes == 16 || dataKeyLengthBytes == 24 || dataKeyLengthBytes == 32)) {
                throw new S3EncryptionClientException("Invalid key length (" + dataKeyLengthBytes + ") in encrypted data key");
            }

            int dataCipherNameLength = pseudoDataKey.length - dataKeyLengthBytes - 1;
            if (dataCipherNameLength <= 0) {
                throw new S3EncryptionClientException("Invalid data cipher name length (" + dataCipherNameLength + ") in encrypted data key");
            }

            byte[] dataKey = new byte[dataKeyLengthBytes];
            byte[] dataCipherName = new byte[dataCipherNameLength];
            System.arraycopy(pseudoDataKey, 1, dataKey, 0, dataKeyLengthBytes);
            System.arraycopy(pseudoDataKey, 1 + dataKeyLengthBytes, dataCipherName, 0, dataCipherNameLength);

            byte[] expectedDataCipherName = materials.algorithmSuite().cipherName().getBytes(StandardCharsets.UTF_8);
            if (!Arrays.equals(expectedDataCipherName, dataCipherName)) {
                throw new S3EncryptionClientException("The data cipher does not match the data cipher used for encryption. The object may be altered or corrupted");
            }

            return dataKey;
        }
    };

    private final Map<String, DecryptDataKeyStrategy> decryptDataKeyStrategies = new HashMap<>();

    private RsaKeyring(Builder builder) {
        super(builder);

        _partialRsaKeyPair = builder._partialRsaKeyPair;

        decryptDataKeyStrategies.put(_rsaStrategy.keyProviderInfo(), _rsaStrategy);
        decryptDataKeyStrategies.put(_rsaEcbStrategy.keyProviderInfo(), _rsaEcbStrategy);
        decryptDataKeyStrategies.put(_rsaOaepStrategy.keyProviderInfo(), _rsaOaepStrategy);
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    protected GenerateDataKeyStrategy generateDataKeyStrategy() {
        return _rsaOaepStrategy;
    }

    @Override
    protected EncryptDataKeyStrategy encryptDataKeyStrategy() {
        return _rsaOaepStrategy;
    }

    @Override
    protected Map<String, DecryptDataKeyStrategy> decryptDataKeyStrategies() {
        return decryptDataKeyStrategies;
    }

    public static class Builder extends S3Keyring.Builder<S3Keyring, Builder> {
        private PartialRsaKeyPair _partialRsaKeyPair;

        private Builder() {
            super();
        }

        @Override
        protected Builder builder() {
            return this;
        }

        public Builder wrappingKeyPair(final PartialRsaKeyPair partialRsaKeyPair) {
            _partialRsaKeyPair = partialRsaKeyPair;
            return builder();
        }

        public RsaKeyring build() {
            return new RsaKeyring(this);
        }
    }

}
