// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.core.ApiName;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Request;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.internal.ApiNameVersion;

//= specification/s3-encryption/materials/s3-kms-keyring.md#interface
//# The KmsKeyring MUST implement the [Keyring interface](keyrings.md#interface) and include the behavior described in the [S3 Keyring](s3-keyring.md).
/**
 * This keyring can wrap keys with the active keywrap algorithm and
 * unwrap with the active and legacy algorithms for KMS keys.
 */
public class KmsKeyring extends S3Keyring {

    private static final ApiName API_NAME = ApiNameVersion.apiNameWithVersion();
    private static final String KEY_ID_CONTEXT_KEY = "kms_cmk_id";

    private final KmsClient _kmsClient;
    private final String _wrappingKeyId;

    //= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
    //# The KmsKeyring MUST NOT support encryption using KmsV1 mode.
    private final DecryptDataKeyStrategy _kmsStrategy = new DecryptDataKeyStrategy() {

        //= specification/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
        //# If the Key Provider Info of the Encrypted Data Key is "kms", the KmsKeyring MUST attempt to decrypt using KmsV1 mode.
        private static final String KEY_PROVIDER_INFO = "kms";

        //= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
        //# The KmsV1 mode MUST be only enabled when legacy wrapping algorithms are enabled.
        @Override
        public boolean isLegacy() {
            return true;
        }

        @Override
        public String keyProviderInfo() {
            return KEY_PROVIDER_INFO;
        }

        //= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
        //# The KmsKeyring MUST support decryption using KmsV1 mode.
        @Override
        public byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey) {
            //= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
            //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key), the
            //# KmsKeyring MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
            DecryptRequest request = DecryptRequest.builder()
                    //= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
                    //# - `KeyId` MUST be the configured AWS KMS key identifier.
                    .keyId(_wrappingKeyId)
                    //= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
                    //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context)
                    //# included in the input [decryption materials](../structures.md#decryption-materials).
                    .encryptionContext(materials.encryptionContext())
                    //= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
                    //# - `CiphertextBlob` MUST be the [encrypted data key ciphertext](../structures.md#ciphertext).
                    .ciphertextBlob(SdkBytes.fromByteArray(encryptedDataKey))
                    //= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
                    //# - A custom API Name or User Agent string SHOULD be provided in order to provide metrics on KMS
                    //# calls associated with the S3 Encryption Client.
                    .overrideConfiguration(builder -> builder.addApiName(API_NAME))
                    .build();

            //= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
            //# If the KmsKeyring fails to successfully decrypt the [encrypted data key](../structures.md#encrypted-data-key), then it MUST throw an exception.
            DecryptResponse response = _kmsClient.decrypt(request);
            //= specification/s3-encryption/materials/s3-kms-keyring.md#kmsv1
            //# The KmsKeyring MUST immediately return the plaintext as a collection of bytes.
            return response.plaintext().asByteArray();
        }
    };

    private final DataKeyStrategy _kmsContextStrategy = new DataKeyStrategy() {

        //= specification/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
        //# If the Key Provider Info of the Encrypted Data Key is "kms+context", the KmsKeyring MUST attempt to decrypt using Kms+Context mode.
        // Support both v2 format ("kms+context") and v3 format ("12") - both use the same strategy
        private static final String KEY_PROVIDER_INFO = "kms+context";
        private static final String ENCRYPTION_CONTEXT_ALGORITHM_KEY = "aws:x-amz-cek-alg";

        //= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
        //# The Kms+Context mode MUST be enabled as a fully-supported (non-legacy) wrapping algorithm.
        @Override
        public boolean isLegacy() {
            return false;
        }

        @Override
        public String keyProviderInfo() {
            // Default to v3 format for new encryptions
            return KEY_PROVIDER_INFO;
        }

        @Override
        public EncryptionMaterials modifyMaterials(EncryptionMaterials materials) {
            S3Request s3Request = materials.s3Request();

            Map<String, String> encryptionContext = new HashMap<>(materials.encryptionContext());
            if (s3Request.overrideConfiguration().isPresent()) {
                AwsRequestOverrideConfiguration overrideConfig = s3Request.overrideConfiguration().get();
                Optional<Map<String, String>> optEncryptionContext = overrideConfig
                        .executionAttributes()
                        .getOptionalAttribute(S3EncryptionClient.ENCRYPTION_CONTEXT);
                optEncryptionContext.ifPresent(encryptionContext::putAll);
            }

            if (encryptionContext.containsKey(ENCRYPTION_CONTEXT_ALGORITHM_KEY)) {
                throw new S3EncryptionClientException(ENCRYPTION_CONTEXT_ALGORITHM_KEY + " is a reserved key for the S3 encryption client");
            }

            if (materials.algorithmSuite().isCommitting()) {
                // This represents the integer value of the Algorithm Suite ID representing the `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY` algorithm suite (0x0073).
                encryptionContext.put(ENCRYPTION_CONTEXT_ALGORITHM_KEY, "115");
            } else {
                encryptionContext.put(ENCRYPTION_CONTEXT_ALGORITHM_KEY, materials.algorithmSuite().cipherName());
            }
            return materials.toBuilder()
                    .encryptionContext(encryptionContext)
                    .build();
        }

        @Override
        public EncryptionMaterials generateDataKey(EncryptionMaterials materials) {
            DataKeySpec dataKeySpec;
            if (!materials.algorithmSuite().dataKeyAlgorithm().equals("AES")) {
                throw new S3EncryptionClientException(String.format("The data key algorithm %s is not supported by AWS " + "KMS", materials.algorithmSuite().dataKeyAlgorithm()));
            }
            switch (materials.algorithmSuite().dataKeyLengthBits()) {
                case 128:
                    dataKeySpec = DataKeySpec.AES_128;
                    break;
                case 256:
                    dataKeySpec = DataKeySpec.AES_256;
                    break;
                default:
                    throw new S3EncryptionClientException(String.format("The data key length %d is not supported by " + "AWS KMS", materials.algorithmSuite().dataKeyLengthBits()));
            }

            GenerateDataKeyRequest request = GenerateDataKeyRequest.builder()
                    .keyId(_wrappingKeyId)
                    .keySpec(dataKeySpec)
                    .encryptionContext(materials.encryptionContext())
                    .overrideConfiguration(builder -> builder.addApiName(API_NAME))
                    .build();
            GenerateDataKeyResponse response = _kmsClient.generateDataKey(request);

            byte[] encryptedDataKeyCiphertext = response.ciphertextBlob().asByteArray();

            EncryptedDataKey encryptedDataKey = EncryptedDataKey.builder()
                    .keyProviderId(S3Keyring.KEY_PROVIDER_ID)
                    .keyProviderInfo(KEY_PROVIDER_INFO)
                    .encryptedDataKey(Objects.requireNonNull(encryptedDataKeyCiphertext))
                    .build();

            List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>(materials.encryptedDataKeys());
            encryptedDataKeys.add(encryptedDataKey);

            return materials.toBuilder()
                    .encryptedDataKeys(encryptedDataKeys)
                    .plaintextDataKey(response.plaintext().asByteArray())
                    .build();
        }

        //= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
        //# The KmsKeyring MUST implement the EncryptDataKey method.
        //= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
        //# The KmsKeyring MUST support encryption using Kms+Context mode.
        @Override
        public byte[] encryptDataKey(SecureRandom secureRandom, EncryptionMaterials materials) {
            HashMap<String, String> encryptionContext = new HashMap<>(materials.encryptionContext());
            EncryptRequest request = EncryptRequest.builder()
                    //= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
                    //# - `KeyId` MUST be the configured AWS KMS key identifier.
                    .keyId(_wrappingKeyId)
                    //= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
                    //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included
                    //# in the input [encryption materials](../structures.md#encryption-materials).
                    .encryptionContext(encryptionContext)
                    //= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
                    //# - `PlaintextDataKey` MUST be the plaintext data key in the [encryption materials](../structures.md#encryption-materials).
                    .plaintext(SdkBytes.fromByteArray(materials.plaintextDataKey()))
                    //= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
                    //# - A custom API Name or User Agent string SHOULD be provided in order to provide metrics on KMS calls associated with the S3 Encryption Client.
                    .overrideConfiguration(builder -> builder.addApiName(API_NAME))
                    .build();

            //= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
            //# The keyring MUST call [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) using the configured AWS KMS client.
            //= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
            //# If the call to [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
            EncryptResponse response = _kmsClient.encrypt(request);
            //= specification/s3-encryption/materials/s3-kms-keyring.md#encryptdatakey
            //# If the call to AWS KMS Encrypt is successful, OnEncrypt MUST return the `CiphertextBlob` as a collection of bytes.
            return response.ciphertextBlob().asByteArray();
        }

        //= specification/s3-encryption/materials/s3-kms-keyring.md#supported-wrapping-algorithm-modes
        //# The KmsKeyring MUST support decryption using Kms+Context mode.
        @Override
        public byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey) {
            Map<String, String> requestEncryptionContext = new HashMap<>();
            GetObjectRequest s3Request = materials.s3Request();
            if (s3Request.overrideConfiguration().isPresent()) {
                AwsRequestOverrideConfiguration overrideConfig = s3Request.overrideConfiguration().get();
                Optional<Map<String, String>> optEncryptionContext = overrideConfig
                        .executionAttributes()
                        .getOptionalAttribute(S3EncryptionClient.ENCRYPTION_CONTEXT);
                if (optEncryptionContext.isPresent()) {
                    requestEncryptionContext = new HashMap<>(optEncryptionContext.get());
                }
            }


            //= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
            //# When decrypting using Kms+Context mode, the KmsKeyring MUST validate the provided (request) encryption context with the stored (materials) encryption context.
            // We are validating the encryption context to match S3EC V2 behavior
            // Refer to KMSMaterialsHandler in the V2 client for details
            Map<String, String> materialsEncryptionContextCopy = new HashMap<>(materials.encryptionContext());
            //= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
            //# The stored encryption context with the two reserved keys removed MUST match the provided encryption context.
            materialsEncryptionContextCopy.remove(KEY_ID_CONTEXT_KEY);
            materialsEncryptionContextCopy.remove(ENCRYPTION_CONTEXT_ALGORITHM_KEY);
            if (!materialsEncryptionContextCopy.equals(requestEncryptionContext)) {
                //= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
                //# If the stored encryption context with the two reserved keys removed does not match the provided encryption context, the KmsKeyring MUST throw an exception.
                throw new S3EncryptionClientException("Provided encryption context does not match information retrieved from S3");
            }

            //= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
            //# To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key), the KmsKeyring
            //# MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.
            DecryptRequest request = DecryptRequest.builder()
                    //= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
                    //# - `KeyId` MUST be the configured AWS KMS key identifier.
                    .keyId(_wrappingKeyId)
                    //= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
                    //# - `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context)
                    //#  included in the input [decryption materials](../structures.md#decryption-materials).
                    .encryptionContext(materials.encryptionContext())
                    //= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
                    //# - `CiphertextBlob` MUST be the [encrypted data key ciphertext](../structures.md#ciphertext).
                    .ciphertextBlob(SdkBytes.fromByteArray(encryptedDataKey))
                    //= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
                    //# - A custom API Name or User Agent string SHOULD be provided in order to provide metrics on KMS calls associated with the S3 Encryption Client.
                    .overrideConfiguration(builder -> builder.addApiName(API_NAME))
                    .build();

            //= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
            //# If the KmsKeyring fails to successfully decrypt the [encrypted data key](../structures.md#encrypted-data-key), then it MUST throw an exception.
            DecryptResponse response = _kmsClient.decrypt(request);
            //= specification/s3-encryption/materials/s3-kms-keyring.md#kms-context
            //# The KmsKeyring MUST immediately return the plaintext as a collection of bytes.
            return response.plaintext().asByteArray();
        }

    };

    private final Map<String, DecryptDataKeyStrategy> decryptDataKeyStrategies = new HashMap<>();

    public KmsKeyring(Builder builder) {
        super(builder);

        _kmsClient = builder._kmsClient;
        _wrappingKeyId = builder._wrappingKeyId;

        //= specification/s3-encryption/materials/s3-kms-keyring.md#decryptdatakey
        //# The KmsKeyring MUST determine whether to decrypt using KmsV1 mode or Kms+Context mode.
        decryptDataKeyStrategies.put(_kmsStrategy.keyProviderInfo(), _kmsStrategy);
        decryptDataKeyStrategies.put(_kmsContextStrategy.keyProviderInfo(), _kmsContextStrategy);
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    protected GenerateDataKeyStrategy generateDataKeyStrategy() {
        return _kmsContextStrategy;
    }

    @Override
    protected EncryptDataKeyStrategy encryptDataKeyStrategy() {
        return _kmsContextStrategy;
    }

    @Override
    protected Map<String, DecryptDataKeyStrategy> decryptDataKeyStrategies() {
        return decryptDataKeyStrategies;
    }

    public static class Builder extends S3Keyring.Builder<KmsKeyring, Builder> {
        private KmsClient _kmsClient;
        private String _wrappingKeyId;

        private Builder() {
            super();
        }

        @Override
        protected Builder builder() {
            return this;
        }

        //= specification/s3-encryption/materials/s3-kms-keyring.md#initialization
        //# On initialization, the caller MAY provide an AWS KMS SDK client instance.
        /**
         * Note that this does NOT create a defensive clone of KmsClient. Any modifications made to the wrapped
         * client will be reflected in this Builder.
         */
        @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "Pass mutability into wrapping client")
        public Builder kmsClient(KmsClient kmsClient) {
            _kmsClient = kmsClient;
            return this;
        }

        //= specification/s3-encryption/materials/s3-kms-keyring.md#initialization
        //# On initialization, the caller MUST provide an AWS KMS key identifier.
        public Builder wrappingKeyId(String wrappingKeyId) {
            if (wrappingKeyId == null || wrappingKeyId.isEmpty()) {
                throw new S3EncryptionClientException("Kms Key ID cannot be empty or null");
            }
            _wrappingKeyId = wrappingKeyId;
            return this;
        }

        public KmsKeyring build() {
            //= specification/s3-encryption/materials/s3-kms-keyring.md#initialization
            //# If the caller does not provide an AWS KMS SDK client instance or provides a null value, the KmsKeyring MUST create a default KMS client instance.
            if (_kmsClient == null) {
                _kmsClient = KmsClient.create();
            }

            return new KmsKeyring(this);
        }
    }
}
