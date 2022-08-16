package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter.JsonGenerationException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
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

/**
 * This Decrypts metadata from Instruction File which is stored parallel to S3 Object.
 * The name is not a typo
 */
public class InstructionFileMetadataDecodingStrategy implements ContentMetadataDecodingStrategy {
    private final Base64.Decoder _decoder;

    private InstructionFileMetadataDecodingStrategy(Builder builder) {
        this._decoder = builder._decoder;
    }

    public static Builder builder() { return new Builder(); }

    @Override
    public ContentMetadata decodeMetadata(Map<String, String> metadata) {

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
                edkCiphertext = _decoder.decode(metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V1));

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
                edkCiphertext = _decoder.decode(metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2));
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

            for (Entry<String, JsonNode> entry : objectNode.asObject().entrySet()) {
                encryptionContext.put(entry.getKey(), entry.getValue().asString());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Get content nonce
        byte[] nonce = _decoder.decode(metadata.get(MetadataKeyConstants.CONTENT_NONCE));

        return ContentMetadata.builder()
                .algorithmSuite(algorithmSuite)
                .encryptedDataKey(edk)
                .encryptedDataKeyContext(encryptionContext)
                .contentNonce(nonce)
                .build();
    }

    public static class Builder {
        private  Base64.Decoder _decoder = Base64.getDecoder();

        public Builder base64Decoder(Base64.Decoder decoder) {
            this._decoder = decoder;
            return this;
        }

        public InstructionFileMetadataDecodingStrategy build() {
            return new InstructionFileMetadataDecodingStrategy(this);
        }
    }
}
