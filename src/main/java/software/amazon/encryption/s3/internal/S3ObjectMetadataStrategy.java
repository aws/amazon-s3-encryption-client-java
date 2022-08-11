package software.amazon.encryption.s3.internal;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter.JsonGenerationException;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.S3Keyring;

/**
 * This stores encryption metadata in the S3 object metadata.
 * The name is not a typo
 */
public class S3ObjectMetadataStrategy implements ContentMetadataEncodingStrategy,
        ContentMetadataDecodingStrategy {
    private final Base64.Encoder _encoder;
    private final Base64.Decoder _decoder;

    private S3ObjectMetadataStrategy(Builder builder) {
        this._encoder = builder._encoder;
        this._decoder = builder._decoder;
    }

    public static Builder builder() { return new Builder(); }

    @Override
    public PutObjectRequest encodeMetadata(
            EncryptionMaterials materials,
            EncryptedContent encryptedContent,
            PutObjectRequest request) {
        Map<String,String> metadata = new HashMap<>(request.metadata());
        EncryptedDataKey edk = materials.encryptedDataKeys().get(0);
        metadata.put(MetadataKey.ENCRYPTED_DATA_KEY_V2, _encoder.encodeToString(edk.ciphertext()));
        metadata.put(MetadataKey.CONTENT_NONCE, _encoder.encodeToString(encryptedContent.nonce));
        metadata.put(MetadataKey.CONTENT_CIPHER, materials.algorithmSuite().cipherName());
        metadata.put(MetadataKey.CONTENT_CIPHER_TAG_LENGTH, Integer.toString(materials.algorithmSuite().cipherTagLengthBits()));
        metadata.put(MetadataKey.ENCRYPTED_DATA_KEY_ALGORITHM, new String(edk.keyProviderInfo(), StandardCharsets.UTF_8));

        try (JsonWriter jsonWriter = JsonWriter.create()) {
            jsonWriter.writeStartObject();
            for (Entry<String,String> entry : materials.encryptionContext().entrySet()) {
                jsonWriter.writeFieldName(entry.getKey()).writeValue(entry.getValue());
            }
            jsonWriter.writeEndObject();

            String jsonEncryptionContext = new String(jsonWriter.getBytes(), StandardCharsets.UTF_8);
            metadata.put(MetadataKey.ENCRYPTED_DATA_KEY_CONTEXT, jsonEncryptionContext);
        } catch (JsonGenerationException e) {
            throw new S3EncryptionClientException("Cannot serialize encryption context to JSON.", e);
        }

        return request.toBuilder().metadata(metadata).build();
    }

    @Override
    public ContentMetadata decodeMetadata(GetObjectResponse response) {
        Map<String, String> metadata = response.metadata();

        // Get algorithm suite
        final String contentEncryptionAlgorithm = metadata.get(MetadataKey.CONTENT_CIPHER);
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
                edkCiphertext = _decoder.decode(metadata.get(MetadataKey.ENCRYPTED_DATA_KEY_V1));

                // Hardcode the key provider id to match what V1 does
                keyProviderInfo = "AES";

                break;
            case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
                // Check tag length
                final int tagLength = Integer.parseInt(metadata.get(MetadataKey.CONTENT_CIPHER_TAG_LENGTH));
                if (tagLength != algorithmSuite.cipherTagLengthBits()) {
                    throw new S3EncryptionClientException("Expected tag length (bits) of: "
                            + algorithmSuite.cipherTagLengthBits()
                            + ", got: " + tagLength);
                }

                // Extract encrypted data key ciphertext and provider id
                edkCiphertext = _decoder.decode(metadata.get(MetadataKey.ENCRYPTED_DATA_KEY_V2));
                keyProviderInfo = metadata.get(MetadataKey.ENCRYPTED_DATA_KEY_ALGORITHM);

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
        final String jsonEncryptionContext = metadata.get(MetadataKey.ENCRYPTED_DATA_KEY_CONTEXT);
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
        byte[] nonce = _decoder.decode(metadata.get(MetadataKey.CONTENT_NONCE));

        return ContentMetadata.builder()
                .algorithmSuite(algorithmSuite)
                .encryptedDataKey(edk)
                .encryptedDataKeyContext(encryptionContext)
                .contentNonce(nonce)
                .build();
    }

    public static class Builder {
        private Base64.Encoder _encoder = Base64.getEncoder();
        private  Base64.Decoder _decoder = Base64.getDecoder();

        public Builder base64Encoder(Base64.Encoder encoder) {
            this._encoder = encoder;
            return this;
        }

        public Builder base64Decoder(Base64.Decoder decoder) {
            this._decoder = decoder;
            return this;
        }

        public S3ObjectMetadataStrategy build() {
            return new S3ObjectMetadataStrategy(this);
        }
    }
}
