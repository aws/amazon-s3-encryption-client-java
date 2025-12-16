// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.encryption.s3.S3EncryptionClientException;

//= specification/s3-encryption/materials/s3-keyring.md#overview
//= type=implication
//# The S3EC SHOULD implement an S3 Keyring to consolidate validation and other functionality common to all S3 Keyrings.
//= specification/s3-encryption/materials/s3-keyring.md#overview
//= type=implication
//# If implemented, the S3 Keyring MUST implement the Keyring interface.
//= specification/s3-encryption/materials/s3-keyring.md#overview
//= type=implication
//# If implemented, the S3 Keyring MUST NOT be able to be instantiated as a Keyring instance.
/**
 * This serves as the base class for all the keyrings in the S3 encryption client.
 * Shared functionality is all performed here.
 */
abstract public class S3Keyring implements Keyring {

    public static final String KEY_PROVIDER_ID = "S3Keyring";
    protected final DataKeyGenerator _dataKeyGenerator;
    private final boolean _enableLegacyWrappingAlgorithms;
    private final SecureRandom _secureRandom;

    protected S3Keyring(Builder<?, ?> builder) {
        _enableLegacyWrappingAlgorithms = builder._enableLegacyWrappingAlgorithms;
        _secureRandom = builder._secureRandom;
        _dataKeyGenerator = builder._dataKeyGenerator;
    }

    /**
     * @return true if legacy wrapping algorithms are enabled, false otherwise
     */
    public boolean areLegacyWrappingAlgorithmsEnabled() { return _enableLegacyWrappingAlgorithms;}

    /**
     * Generates a data key using the provided EncryptionMaterials and the configured DataKeyGenerator.
     * <p>
     * This method is intended for extension by customers who need to customize key generation within their Keyring
     * implementation. It generates a data key for encryption using the algorithm suite and cryptographic provider
     * configured in the provided EncryptionMaterials object.
     *
     * @param materials The EncryptionMaterials containing information about the algorithm suite and cryptographic
     *                  provider to be used for data key generation.
     * @return An updated EncryptionMaterials object with the generated plaintext data key.
     */
    public EncryptionMaterials defaultGenerateDataKey(EncryptionMaterials materials) {
        SecretKey dataKey = _dataKeyGenerator.generateDataKey(materials.algorithmSuite(), materials.cryptoProvider());
        return materials.toBuilder()
                .plaintextDataKey(dataKey.getEncoded())
                .build();
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials materials) {
        EncryptDataKeyStrategy encryptStrategy = encryptDataKeyStrategy();

        // Allow encrypt strategy to modify the materials if necessary
        materials = encryptStrategy.modifyMaterials(materials);

        //= specification/s3-encryption/materials/s3-keyring.md#onencrypt
        //= type=implication
        //# If the Plaintext Data Key in the input EncryptionMaterials is null, the S3 Keyring MUST call the GenerateDataKey method using the materials.
        if (materials.plaintextDataKey() == null) {
            materials = generateDataKeyStrategy().generateDataKey(materials);
        }

        //= specification/s3-encryption/materials/s3-keyring.md#onencrypt
        //= type=implication
        //# If the materials returned from GenerateDataKey contain an EncryptedDataKey, the S3 Keyring MUST return the materials.
        if (!materials.encryptedDataKeys().isEmpty()) {
            return materials;
        }

        try {
            //= specification/s3-encryption/materials/s3-keyring.md#onencrypt
            //= type=implication
            //# If the materials returned from GenerateDataKey do not contain an EncryptedDataKey, the S3 Keyring MUST call the EncryptDataKey method using the materials.
            byte[] encryptedDataKeyCiphertext = encryptStrategy.encryptDataKey(_secureRandom, materials);
            EncryptedDataKey encryptedDataKey = EncryptedDataKey.builder()
                    .keyProviderId(S3Keyring.KEY_PROVIDER_ID)
                    .keyProviderInfo(encryptStrategy.keyProviderInfo())
                    .encryptedDataKey(encryptedDataKeyCiphertext)
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

    //= specification/s3-encryption/materials/s3-keyring.md#abstract-methods
    //= type=implication
    //# - The S3 Keyring MUST define an abstract method GenerateDataKey.
    abstract protected GenerateDataKeyStrategy generateDataKeyStrategy();

    //= specification/s3-encryption/materials/s3-keyring.md#abstract-methods
    //= type=implication
    //# - The S3 Keyring MUST define an abstract method EncryptDataKey.
    abstract protected EncryptDataKeyStrategy encryptDataKeyStrategy();

    @Override
    public DecryptionMaterials onDecrypt(final DecryptionMaterials materials, List<EncryptedDataKey> encryptedDataKeys) {
        //= specification/s3-encryption/materials/s3-keyring.md#ondecrypt
        //= type=implication
        //# If the input DecryptionMaterials contains a Plaintext Data Key, the S3 Keyring MUST throw an exception.
        if (materials.plaintextDataKey() != null) {
            throw new S3EncryptionClientException("Decryption materials already contains a plaintext data key.");
        }

        //= specification/s3-encryption/materials/s3-keyring.md#ondecrypt
        //= type=implication
        //# If the input collection of EncryptedDataKey instances contains any number of EDKs other than 1, the S3 Keyring MUST throw an exception.
        if (encryptedDataKeys.size() != 1) {
            throw new S3EncryptionClientException("Only one encrypted data key is supported, found: " + encryptedDataKeys.size());
        }

        //= specification/s3-encryption/materials/s3-keyring.md#ondecrypt
        //= type=implication
        //# The S3 Keyring MAY validate that the Key Provider ID of the Encrypted Data Key matches the expected default Key Provider ID value.
        EncryptedDataKey encryptedDataKey = encryptedDataKeys.get(0);
        final String keyProviderId = encryptedDataKey.keyProviderId();
        if (!KEY_PROVIDER_ID.equals(keyProviderId)) {
            throw new S3EncryptionClientException("Unknown key provider: " + keyProviderId);
        }

        String keyProviderInfo = encryptedDataKey.keyProviderInfo();

        DecryptDataKeyStrategy decryptStrategy = decryptDataKeyStrategies().get(keyProviderInfo);
        if (decryptStrategy == null) {
            throw new S3EncryptionClientException("The keyring does not support the object's key wrapping algorithm: " + keyProviderInfo);
        }

        //= specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
        //= type=implication
        //# When enabled, the S3EC MUST be able to decrypt objects encrypted with all supported wrapping algorithms (both legacy and fully supported).
        if (decryptStrategy.isLegacy() && !_enableLegacyWrappingAlgorithms) {
            //= specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
            //= type=implementation
            //# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy wrapping algorithms; it MUST throw an exception when attempting to decrypt an object encrypted with a legacy wrapping algorithm.
            throw new S3EncryptionClientException("Enable legacy wrapping algorithms to use legacy key wrapping algorithm: " + keyProviderInfo);
        }

        try {
            //= specification/s3-encryption/materials/s3-keyring.md#ondecrypt
            //= type=implication
            //# The S3 Keyring MUST call the DecryptDataKey method using the materials and add the resulting plaintext data key to the materials.
            byte[] plaintext = decryptStrategy.decryptDataKey(materials, encryptedDataKey.encryptedDatakey());
            return materials.toBuilder().plaintextDataKey(plaintext).build();
        } catch (GeneralSecurityException e) {
            throw new S3EncryptionClientException("Unable to " + keyProviderInfo + " unwrap", e);
        }
    }

    //= specification/s3-encryption/materials/s3-keyring.md#abstract-methods
    //= type=implication
    //# - The S3 Keyring MUST define an abstract method DecryptDataKey.
    abstract protected Map<String, DecryptDataKeyStrategy> decryptDataKeyStrategies();

    abstract public static class Builder<KeyringT extends S3Keyring, BuilderT extends Builder<KeyringT, BuilderT>> {
        private boolean _enableLegacyWrappingAlgorithms = false;
        private SecureRandom _secureRandom = new SecureRandom();
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
