package software.amazon.encryption.s3.internal;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter.JsonGenerationException;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.S3Keyring;

public abstract class ContentMetadataStrategy implements ContentMetadataEncodingStrategy, ContentMetadataDecodingStrategy {

    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    public static final ContentMetadataDecodingStrategy INSTRUCTION_FILE = new ContentMetadataDecodingStrategy() {

        private static final String FILE_SUFFIX = ".instruction";

        @Override
        public ContentMetadata decodeMetadata(S3Client client, GetObjectRequest getObjectRequest, GetObjectResponse response) {
            GetObjectRequest instructionGetObjectRequest = GetObjectRequest.builder()
                    .bucket(getObjectRequest.bucket())
                    .key(getObjectRequest.key() + FILE_SUFFIX)
                    .build();
            ResponseInputStream<GetObjectResponse> instruction = client.getObject(
                    instructionGetObjectRequest);

            Map<String, String> metadata = new HashMap<>();
            JsonNodeParser parser = JsonNodeParser.create();
            JsonNode objectNode = parser.parse(instruction);
            for (Map.Entry<String, JsonNode> entry : objectNode.asObject().entrySet()) {
                metadata.put(entry.getKey(), entry.getValue().asString());
            }

            return ContentMetadataStrategy.readFromMap(metadata);
        }
    };

    public static final ContentMetadataStrategy OBJECT_METADATA = new ContentMetadataStrategy() {

        @Override
        public PutObjectRequest encodeMetadata(EncryptionMaterials materials,
                EncryptedContent encryptedContent, PutObjectRequest request) {
            Map<String,String> metadata = new HashMap<>(request.metadata());
            EncryptedDataKey edk = materials.encryptedDataKeys().get(0);
            metadata.put(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2, ENCODER.encodeToString(edk.ciphertext()));
            metadata.put(MetadataKeyConstants.CONTENT_NONCE, ENCODER.encodeToString(encryptedContent.nonce));
            metadata.put(MetadataKeyConstants.CONTENT_CIPHER, materials.algorithmSuite().cipherName());
            metadata.put(MetadataKeyConstants.CONTENT_CIPHER_TAG_LENGTH, Integer.toString(materials.algorithmSuite().cipherTagLengthBits()));
            metadata.put(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM, new String(edk.keyProviderInfo(), StandardCharsets.UTF_8));

            try (JsonWriter jsonWriter = JsonWriter.create()) {
                jsonWriter.writeStartObject();
                for (Entry<String,String> entry : materials.encryptionContext().entrySet()) {
                    jsonWriter.writeFieldName(entry.getKey()).writeValue(entry.getValue());
                }
                jsonWriter.writeEndObject();

                String jsonEncryptionContext = new String(jsonWriter.getBytes(), StandardCharsets.UTF_8);
                metadata.put(MetadataKeyConstants.ENCRYPTED_DATA_KEY_CONTEXT, jsonEncryptionContext);
            } catch (JsonGenerationException e) {
                throw new S3EncryptionClientException("Cannot serialize encryption context to JSON.", e);
            }

            return request.toBuilder().metadata(metadata).build();
        }

        @Override
        public ContentMetadata decodeMetadata(S3Client client, GetObjectRequest request, GetObjectResponse response) {
            return ContentMetadataStrategy.readFromMap(response.metadata());
        }
    };

    private static ContentMetadata readFromMap(Map<String, String> metadata) {
        // Get algorithm suite
        final String contentEncryptionAlgorithm = metadata.get(MetadataKeyConstants.CONTENT_CIPHER);
        AlgorithmSuite algorithmSuite;
        if (contentEncryptionAlgorithm == null
                || contentEncryptionAlgorithm.equals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF.cipherName())) {
            algorithmSuite = AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF;
        } else if (contentEncryptionAlgorithm.equals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherName())) {
            algorithmSuite = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
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
                .ciphertext(edkCiphertext)
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
                .build();
    }

    public static ContentMetadata decode(S3Client client, GetObjectRequest request, GetObjectResponse response) {
        Map<String, String> metadata = response.metadata();
        ContentMetadataDecodingStrategy strategy;
        if (metadata != null
            && metadata.containsKey(MetadataKeyConstants.CONTENT_NONCE)
            && (metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V1)
                || metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2))) {
            strategy = OBJECT_METADATA;
        } else {
            strategy = INSTRUCTION_FILE;
        }

        return strategy.decodeMetadata(client, request, response);
    }
}
