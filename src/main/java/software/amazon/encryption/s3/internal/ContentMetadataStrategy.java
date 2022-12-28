package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter.JsonGenerationException;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
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
import java.util.concurrent.ExecutionException;

import static software.amazon.encryption.s3.S3EncryptionClientUtilities.INSTRUCTION_FILE_SUFFIX;

public abstract class ContentMetadataStrategy implements ContentMetadataEncodingStrategy, ContentMetadataDecodingStrategy {

    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    public static final ContentMetadataDecodingStrategy INSTRUCTION_FILE = new ContentMetadataDecodingStrategy() {

        @Override
        public ContentMetadata decodeMetadata(ResponseBytes<GetObjectResponse> instruction, GetObjectResponse response) {
            Map<String, String> metadata = new HashMap<>();
            JsonNodeParser parser = JsonNodeParser.create();
            JsonNode objectNode = parser.parse(instruction.asByteArray());
            for (Map.Entry<String, JsonNode> entry : objectNode.asObject().entrySet()) {
                metadata.put(entry.getKey(), entry.getValue().asString());
            }
            return ContentMetadataStrategy.readFromMap(metadata, response);
        }
    };

    public static final ContentMetadataStrategy OBJECT_METADATA = new ContentMetadataStrategy() {

        @Override
        public Map<String, String> encodeMetadata(EncryptionMaterials materials, byte[] nonce,
                                                  Map<String, String> metadata) {
            EncryptedDataKey edk = materials.encryptedDataKeys().get(0);
            metadata.put(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2, ENCODER.encodeToString(edk.encryptedDatakey()));
            metadata.put(MetadataKeyConstants.CONTENT_NONCE, ENCODER.encodeToString(nonce));
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
        public ContentMetadata decodeMetadata(ResponseBytes<GetObjectResponse> instruction, GetObjectResponse response) {
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
            algorithmSuite = (contentRange == null) ? AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF : AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF;
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
                edkCiphertext = DECODER.decode(metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V1));

                // Hardcode the key provider id to match what V1 does
                keyProviderInfo = "AES";

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

        // Get content nonce
        byte[] nonce = DECODER.decode(metadata.get(MetadataKeyConstants.CONTENT_NONCE));

        return ContentMetadata.builder()
                .algorithmSuite(algorithmSuite)
                .encryptedDataKey(edk)
                .encryptedDataKeyContext(encryptionContext)
                .contentNonce(nonce)
                .contentRange(contentRange)
                .build();
    }

    public static ContentMetadata decode(S3Client client, GetObjectRequest request, GetObjectResponse response) {
        Map<String, String> metadata = response.metadata();
        ContentMetadataDecodingStrategy strategy;
        ResponseBytes<GetObjectResponse> instruction = null;
        if (metadata != null
                && metadata.containsKey(MetadataKeyConstants.CONTENT_NONCE)
                && (metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V1)
                || metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2))) {
            strategy = OBJECT_METADATA;
        } else {
            strategy = INSTRUCTION_FILE;
            GetObjectRequest instructionGetObjectRequest = GetObjectRequest.builder()
                    .bucket(request.bucket())
                    .key(request.key() + INSTRUCTION_FILE_SUFFIX)
                    .build();

            instruction = client.getObjectAsBytes(
                    instructionGetObjectRequest);
        }

        return strategy.decodeMetadata(instruction, response);
    }

    public static ContentMetadata decode(S3AsyncClient client, GetObjectRequest request, GetObjectResponse response) {
        Map<String, String> metadata = response.metadata();
        ContentMetadataDecodingStrategy strategy;
        ResponseBytes<GetObjectResponse> instruction = null;
        if (metadata != null
                && metadata.containsKey(MetadataKeyConstants.CONTENT_NONCE)
                && (metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V1)
                || metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2))) {
            strategy = OBJECT_METADATA;
        } else {
            strategy = INSTRUCTION_FILE;
            GetObjectRequest instructionGetObjectRequest = GetObjectRequest.builder()
                    .bucket(request.bucket())
                    .key(request.key() + INSTRUCTION_FILE_SUFFIX)
                    .build();
            try {
                instruction = client.getObject(instructionGetObjectRequest,
                        AsyncResponseTransformer.toBytes()).get();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            } catch (ExecutionException e) {
                throw new RuntimeException(e);
            }
        }

        return strategy.decodeMetadata(instruction, response);
    }
}
