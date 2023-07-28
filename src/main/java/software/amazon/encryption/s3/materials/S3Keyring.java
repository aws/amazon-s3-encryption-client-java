// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.encryption.s3.S3EncryptionClientException;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * This serves as the base class for all the keyrings in the S3 encryption client.
 * Shared functionality is all performed here.
 */
abstract public class S3Keyring implements Keyring {

    public static final String KEY_PROVIDER_ID = "S3Keyring";

    private final boolean _enableLegacyWrappingAlgorithms;
    private final SecureRandom _secureRandom;
    private final DataKeyGenerator _dataKeyGenerator;

    protected S3Keyring(Builder<?,?> builder) {
        _enableLegacyWrappingAlgorithms = builder._enableLegacyWrappingAlgorithms;
        _secureRandom = builder._secureRandom;
        _dataKeyGenerator = builder._dataKeyGenerator;
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials materials) {
        EncryptDataKeyStrategy encryptStrategy = encryptStrategy();
        try {
            if (materials.plaintextDataKey() == null && !encryptStrategy.isKms()) {
                SecretKey dataKey = _dataKeyGenerator.generateDataKey(materials.algorithmSuite(), materials.cryptoProvider());
                materials = materials.toBuilder()
                        .plaintextDataKey(dataKey.getEncoded())
                        .build();
            }

            // Allow encrypt strategy to modify the materials if necessary
            materials = encryptStrategy.modifyMaterials(materials);

            byte[] encryptedDataKeyCiphertext;

            if (encryptStrategy.isKms()) {
                // Since generateDataKey already performs the Encrypt operation and
                // returns both plaintext and ciphertext data keys,
                // calling encryptDataKey separately is not required.
                GenerateDataKeyResponse response = encryptStrategy.generateDataKey(materials);
                materials = materials.toBuilder()
                        .plaintextDataKey(response.plaintext().asByteArray())
                        .build();
                encryptedDataKeyCiphertext = response.ciphertextBlob().asByteArray();
            } else {
                encryptedDataKeyCiphertext = encryptStrategy.encryptDataKey(_secureRandom, materials);
            }

            EncryptedDataKey encryptedDataKey = EncryptedDataKey.builder()
                    .keyProviderId(S3Keyring.KEY_PROVIDER_ID)
                    .keyProviderInfo(encryptStrategy.keyProviderInfo().getBytes(StandardCharsets.UTF_8))
                    .encryptedDataKey(Objects.requireNonNull(encryptedDataKeyCiphertext))
                    .build();

            List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>(materials.encryptedDataKeys());
            encryptedDataKeys.add(encryptedDataKey);

            return materials.toBuilder()
                    .encryptedDataKeys(encryptedDataKeys)
                    .build();
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to " + encryptStrategy.keyProviderInfo() + " wrap", e);
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
        if (!KEY_PROVIDER_ID.equals(keyProviderId)) {
            throw new S3EncryptionClientException("Unknown key provider: " + keyProviderId);
        }

        String keyProviderInfo = new String(encryptedDataKey.keyProviderInfo(), StandardCharsets.UTF_8);

        DecryptDataKeyStrategy decryptStrategy = decryptStrategies().get(keyProviderInfo);
        if (decryptStrategy == null) {
            throw new S3EncryptionClientException("The keyring does not support the object's key wrapping algorithm: " + keyProviderInfo);
        }

        if (decryptStrategy.isLegacy() && !_enableLegacyWrappingAlgorithms) {
            throw new S3EncryptionClientException("Enable legacy wrapping algorithms to use legacy key wrapping algorithm: " + keyProviderInfo);
        }

        try {
            byte[] plaintext = decryptStrategy.decryptDataKey(materials, encryptedDataKey.encryptedDatakey());
            return materials.toBuilder().plaintextDataKey(plaintext).build();
        } catch (GeneralSecurityException e) {
            throw new S3EncryptionClientException("Unable to " + keyProviderInfo + " unwrap", e);
        }
    }

    abstract protected Map<String,DecryptDataKeyStrategy> decryptStrategies();

    abstract public static class Builder<KeyringT extends S3Keyring, BuilderT extends Builder<KeyringT, BuilderT>> {
        private boolean _enableLegacyWrappingAlgorithms = false;
        private SecureRandom _secureRandom;
        private DataKeyGenerator _dataKeyGenerator = new DefaultDataKeyGenerator();


        protected Builder() {}

        protected abstract BuilderT builder();

        public BuilderT enableLegacyWrappingAlgorithms(boolean shouldEnableLegacyWrappingAlgorithms) {
            this._enableLegacyWrappingAlgorithms = shouldEnableLegacyWrappingAlgorithms;
            return builder();
        }

        /**
         * Note that this does NOT create a defensive copy of the SecureRandom object. Any modifications to the
         * object will be reflected in this Builder.
         */
        @SuppressFBWarnings(value = "EI_EXPOSE_REP")
        public BuilderT secureRandom(final SecureRandom secureRandom) {
            if (secureRandom == null) {
                throw new S3EncryptionClientException("SecureRandom provided to S3Keyring cannot be null");
            }
            _secureRandom = secureRandom;
            return builder();
        }

        public BuilderT dataKeyGenerator(final DataKeyGenerator dataKeyGenerator) {
            if (dataKeyGenerator == null) {
                throw new S3EncryptionClientException("DataKeyGenerator cannot be null!");
            }
            _dataKeyGenerator = dataKeyGenerator;
            return builder();
        }

        abstract public KeyringT build();
    }
}
