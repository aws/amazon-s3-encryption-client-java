package software.amazon.encryption.s3.internal;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter.JsonGenerationException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.internal.PutEncryptedObjectPipeline.EncryptedContent;
import software.amazon.encryption.s3.internal.PutEncryptedObjectPipeline.MetadataEncodingStrategy;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

/**
 * This stores encryption metadata in the S3 object metadata.
 * The name is not a typo
 */
public class ObjectMetadataMetadataEncodingStrategy implements MetadataEncodingStrategy {
    private final Base64.Encoder _encoder;

    private ObjectMetadataMetadataEncodingStrategy(Builder builder) {
        this._encoder = builder._encoder;
    }

    public static Builder builder() { return new Builder(); }

    @Override
    public PutObjectRequest encodeMetadata(
            EncryptionMaterials materials,
            EncryptedContent encryptedContent,
            PutObjectRequest request) {
        Map<String,String> metadata = new HashMap<>(request.metadata());
        EncryptedDataKey edk = materials.encryptedDataKeys().get(0);
        metadata.put(MetadataKey.ENCRYPTED_DATA_KEY, _encoder.encodeToString(edk.ciphertext()));
        metadata.put(MetadataKey.CONTENT_NONCE, _encoder.encodeToString(encryptedContent.nonce));
        metadata.put(MetadataKey.CONTENT_CIPHER, materials.algorithmSuite().cipherName());
        metadata.put(MetadataKey.CONTENT_CIPHER_TAG_LENGTH, Integer.toString(materials.algorithmSuite().cipherTagLengthBits()));
        metadata.put(MetadataKey.ENCRYPTED_DATA_KEY_ALGORITHM, edk.keyProviderId());

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

    public static class Builder {
        private Base64.Encoder _encoder = Base64.getEncoder();

        public Builder base64Encoder(Base64.Encoder encoder) {
            this._encoder = encoder;
            return this;
        }

        public ObjectMetadataMetadataEncodingStrategy build() {
            return new ObjectMetadataMetadataEncodingStrategy(this);
        }
    }
}
