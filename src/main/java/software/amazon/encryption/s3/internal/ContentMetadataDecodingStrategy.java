// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.S3Keyring;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static software.amazon.encryption.s3.S3EncryptionClientUtilities.INSTRUCTION_FILE_SUFFIX;

public class ContentMetadataDecodingStrategy {

    private static final Base64.Decoder DECODER = Base64.getDecoder();

    private final S3AsyncClient wrappedAsyncClient_;

    public ContentMetadataDecodingStrategy(S3AsyncClient s3AsyncClient) {
        if (s3AsyncClient == null) {
            throw new S3EncryptionClientException("ContentMetadataDecodingStrategy requires a non-null async client.");
        }
        wrappedAsyncClient_ = s3AsyncClient;
    }

    private ContentMetadata readFromMap(Map<String, String> metadata, GetObjectResponse response) {
        // Get algorithm suite
        final String contentEncryptionAlgorithm = metadata.get(MetadataKeyConstants.CONTENT_CIPHER);
        AlgorithmSuite algorithmSuite;
        String contentRange = response.contentRange();
        if (contentEncryptionAlgorithm == null
                || contentEncryptionAlgorithm.equals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF.cipherName())) {
            algorithmSuite = AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF;
        } else if (contentEncryptionAlgorithm.equals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherName())) {
            // If contentRange is provided, this is a ranged get.
            // ranged gets require legacy unauthenticated modes.
            // Change AES-GCM to AES-CTR to disable authentication when reading this message.
            algorithmSuite = (contentRange == null)
                    ? AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
                    : AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF;
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

    public ContentMetadata decode(GetObjectRequest request, GetObjectResponse response) {
        Map<String, String> metadata = response.metadata();
        ContentMetadataDecodingStrategy strategy;
        if (metadata != null
                && metadata.containsKey(MetadataKeyConstants.CONTENT_IV)
                && (metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V1)
                || metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2))) {
            return decodeFromObjectMetadata(request, response);
        } else {
            return decodeFromInstructionFile(request, response);
        }
    }

    private ContentMetadata decodeFromObjectMetadata(GetObjectRequest request, GetObjectResponse response) {
        return readFromMap(response.metadata(), response);
    }

    private ContentMetadata decodeFromInstructionFile(GetObjectRequest request, GetObjectResponse response) {
        GetObjectRequest instructionGetObjectRequest = GetObjectRequest.builder()
                .bucket(request.bucket())
                .key(request.key() + INSTRUCTION_FILE_SUFFIX)
                .build();

        ResponseInputStream<GetObjectResponse> instruction;
        try {
            instruction = wrappedAsyncClient_.getObject(instructionGetObjectRequest, AsyncResponseTransformer.toBlockingInputStream()).join();
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
        return readFromMap(metadata, response);
    }
}
