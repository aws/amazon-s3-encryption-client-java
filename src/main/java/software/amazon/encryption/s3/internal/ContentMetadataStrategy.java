// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter.JsonGenerationException;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.S3Keyring;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import static software.amazon.encryption.s3.S3EncryptionClientUtilities.INSTRUCTION_FILE_SUFFIX;

public abstract class ContentMetadataStrategy implements ContentMetadataEncodingStrategy, ContentMetadataDecodingStrategy {

    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    public static final ContentMetadataDecodingStrategy INSTRUCTION_FILE = new ContentMetadataDecodingStrategy() {

        @Override
        public ContentMetadata decodeMetadata(GetObjectRequest getObjectRequest, GetObjectResponse response) {
            GetObjectRequest instructionGetObjectRequest = GetObjectRequest.builder()
                    .bucket(getObjectRequest.bucket())
                    .key(getObjectRequest.key() + INSTRUCTION_FILE_SUFFIX)
                    .build();

            S3Client s3Client = S3Client.create();
            ResponseInputStream<GetObjectResponse> instruction;
            try {
                instruction = s3Client.getObject(instructionGetObjectRequest);
            } catch (NoSuchKeyException exception) {
                // Most likely, the customer is attempting to decrypt an object
                // which is not encrypted with the S3 EC.
                throw new S3EncryptionClientException("Instruction file not found! Please ensure the object you are" +
                        " attempting to decrypt has been encrypted using the S3 Encryption Client.", exception);
            }

            Map<String, String> metadata = new HashMap<>();
            JsonNodeParser parser = JsonNodeParser.create();
            JsonNode objectNode = parser.parse(instruction);
            for (Map.Entry<String, JsonNode> entry : objectNode.asObject().entrySet()) {
                metadata.put(entry.getKey(), entry.getValue().asString());
            }
            return ContentMetadataStrategy.readFromMap(metadata, response);
        }
    };

    public static final ContentMetadataStrategy OBJECT_METADATA = new ContentMetadataStrategy() {

        @Override
        public Map<String, String> encodeMetadata(EncryptionMaterials materials, byte[] iv,
                                                   Map<String, String> metadata) {
            EncryptedDataKey edk = materials.encryptedDataKeys().get(0);
            metadata.put(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2, ENCODER.encodeToString(edk.encryptedDatakey()));
            metadata.put(MetadataKeyConstants.CONTENT_IV, ENCODER.encodeToString(iv));
            metadata.put(MetadataKeyConstants.CONTENT_CIPHER, materials.algorithmSuite().cipherName());
            metadata.put(MetadataKeyConstants.CONTENT_CIPHER_TAG_LENGTH, Integer.toString(materials.algorithmSuite().cipherTagLengthBits()));
            metadata.put(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM, new String(edk.keyProviderInfo(), StandardCharsets.UTF_8));

            try (JsonWriter jsonWriter = JsonWriter.create()) {
                jsonWriter.writeStartObject();
                for (Entry<String, String> entry : materials.encryptionContext().entrySet()) {
                    jsonWriter.writeFieldName(entry.getKey()).writeValue(entry.getValue());
                }
                jsonWriter.writeEndObject();

                String jsonEncryptionContext = new String(jsonWriter.getBytes(), StandardCharsets.UTF_8);
                metadata.put(MetadataKeyConstants.ENCRYPTED_DATA_KEY_CONTEXT, jsonEncryptionContext);
            } catch (JsonGenerationException e) {
                throw new S3EncryptionClientException("Cannot serialize encryption context to JSON.", e);
            }
            return metadata;
        }

        @Override
        public ContentMetadata decodeMetadata(GetObjectRequest request, GetObjectResponse response) {
            return ContentMetadataStrategy.readFromMap(response.metadata(), response);
        }
    };

    private static ContentMetadata readFromMap(Map<String, String> metadata, GetObjectResponse response) {
        // Get algorithm suite
        final String contentEncryptionAlgorithm = metadata.get(MetadataKeyConstants.CONTENT_CIPHER);
        AlgorithmSuite algorithmSuite;
        String contentRange = response.contentRange();
        if (contentEncryptionAlgorithm == null
                || contentEncryptionAlgorithm.equals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF.cipherName())) {
            algorithmSuite = AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF;
        } else if (contentEncryptionAlgorithm.equals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherName())) {
            algorithmSuite = (contentRange == null ) ? AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF : AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF;
        } else {
            throw new S3EncryptionClientException(
                    "Unknown content encryption algorithm: " + contentEncryptionAlgorithm);
        }

        // Do algorithm suite dependent decoding
        byte[] edkCiphertext;

        // Currently, this is not stored within the metadata,
        // signal to keyring(s) intended for S3EC
        final String keyProviderId = S3Keyring.KEY_PROVIDER_ID;
        String keyProviderInfo;
        switch (algorithmSuite) {
            case ALG_AES_256_CBC_IV16_NO_KDF:
                // Extract encrypted data key ciphertext
                if (metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V1)) {
                    edkCiphertext = DECODER.decode(metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V1));
                } else if (metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2)) {
                    // when using v1 to encrypt in its default mode, it may use the v2 EDK key
                    // despite also using CBC as the content encryption algorithm, presumably due
                    // to how the v2 changes were backported to v1
                    edkCiphertext = DECODER.decode(metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2));
                } else {
                    // this shouldn't happen under normal circumstances- only if out-of-band modification
                    // to the metadata is performed. it is most likely that the data is unrecoverable in this case
                    throw new S3EncryptionClientException("Malformed object metadata! Could not find the encrypted data key.");
                }

                if (!metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM)) {
                    /*
                    For legacy v1 EncryptionOnly objects,
                    there is no EDK algorithm given, it is either plain AES or RSA
                    In v3, we infer AES vs. RSA based on the length of the ciphertext.

                    In v1, whichever key material is provided in its EncryptionMaterials
                    is used to decrypt the EDK.

                    In v3, this is not possible as the keyring code is factored such that
                    the keyProviderInfo is known before the keyring is known.
                    Ciphertext size is expected to be reliable as no AES data key should
                    exceed 256 bits (32 bytes) + 16 padding bytes.

                    In the unlikely event that this assumption is false, the fix would be
                    to refactor the keyring to always use the material given instead of
                    inferring it this way.
                    */
                    if (edkCiphertext.length > 48) {
                        keyProviderInfo = "RSA";
                    } else {
                        keyProviderInfo = "AES";
                    }
                } else {
                    keyProviderInfo = metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM);
                }
                break;
            case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
            case ALG_AES_256_CTR_IV16_TAG16_NO_KDF:
                // Check tag length
                final int tagLength = Integer.parseInt(metadata.get(MetadataKeyConstants.CONTENT_CIPHER_TAG_LENGTH));
                if (tagLength != algorithmSuite.cipherTagLengthBits()) {
                    throw new S3EncryptionClientException("Expected tag length (bits) of: "
                            + algorithmSuite.cipherTagLengthBits()
                            + ", got: " + tagLength);
                }

                // Extract encrypted data key ciphertext and provider id
                edkCiphertext = DECODER.decode(metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2));
                keyProviderInfo = metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM);

                break;
            default:
                throw new S3EncryptionClientException(
                        "Unknown content encryption algorithm: " + algorithmSuite.id());
        }

        // Build encrypted data key
        EncryptedDataKey edk = EncryptedDataKey.builder()
                .encryptedDataKey(edkCiphertext)
                .keyProviderId(keyProviderId)
                .keyProviderInfo(keyProviderInfo.getBytes(StandardCharsets.UTF_8))
                .build();

        // Get encrypted data key encryption context
        final Map<String, String> encryptionContext = new HashMap<>();
        final String jsonEncryptionContext = metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_CONTEXT);
        try {
            JsonNodeParser parser = JsonNodeParser.create();
            JsonNode objectNode = parser.parse(jsonEncryptionContext);

            for (Map.Entry<String, JsonNode> entry : objectNode.asObject().entrySet()) {
                encryptionContext.put(entry.getKey(), entry.getValue().asString());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Get content iv
        byte[] iv = DECODER.decode(metadata.get(MetadataKeyConstants.CONTENT_IV));

        return ContentMetadata.builder()
                .algorithmSuite(algorithmSuite)
                .encryptedDataKey(edk)
                .encryptedDataKeyContext(encryptionContext)
                .contentIv(iv)
                .contentRange(contentRange)
                .build();
    }

    public static ContentMetadata decode(GetObjectRequest request, GetObjectResponse response) {
        Map<String, String> metadata = response.metadata();
        ContentMetadataDecodingStrategy strategy;
        if (metadata != null
                && metadata.containsKey(MetadataKeyConstants.CONTENT_IV)
                && (metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V1)
                || metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2))) {
            strategy = OBJECT_METADATA;
        } else {
            strategy = INSTRUCTION_FILE;
        }

        return strategy.decodeMetadata(request, response);
    }
}
