package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.protocols.jsoncore.JsonWriter;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class ObjectMetadataEncodingStrategy implements ContentMetadataEncodingStrategy {

    private static final Base64.Encoder ENCODER = Base64.getEncoder();

    public PutObjectRequest encodeMetadata(EncryptionMaterials materials, byte[] iv, PutObjectRequest putObjectRequest) {
        Map<String, String> newMetadata = addMetadataToMap(putObjectRequest.metadata(), materials, iv);
        return putObjectRequest.toBuilder()
                .metadata(newMetadata)
                .build();
    }

    public CreateMultipartUploadRequest encodeMetadata(EncryptionMaterials materials, byte[] iv, CreateMultipartUploadRequest createMultipartUploadRequest) {
        Map<String, String> newMetadata = addMetadataToMap(createMultipartUploadRequest.metadata(), materials, iv);
        return createMultipartUploadRequest.toBuilder()
                .metadata(newMetadata)
                .build();
    }

    private Map<String, String> addMetadataToMap(Map<String, String> map, EncryptionMaterials materials, byte[] iv) {
        Map<String, String> metadata = new HashMap<>(map);
        EncryptedDataKey edk = materials.encryptedDataKeys().get(0);
        metadata.put(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2, ENCODER.encodeToString(edk.encryptedDatakey()));
        metadata.put(MetadataKeyConstants.CONTENT_IV, ENCODER.encodeToString(iv));
        metadata.put(MetadataKeyConstants.CONTENT_CIPHER, materials.algorithmSuite().cipherName());
        metadata.put(MetadataKeyConstants.CONTENT_CIPHER_TAG_LENGTH, Integer.toString(materials.algorithmSuite().cipherTagLengthBits()));
        metadata.put(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM, new String(edk.keyProviderInfo(), StandardCharsets.UTF_8));

        try (JsonWriter jsonWriter = JsonWriter.create()) {
            jsonWriter.writeStartObject();
            for (Map.Entry<String, String> entry : materials.encryptionContext().entrySet()) {
                jsonWriter.writeFieldName(entry.getKey()).writeValue(entry.getValue());
            }
            jsonWriter.writeEndObject();

            String jsonEncryptionContext = new String(jsonWriter.getBytes(), StandardCharsets.UTF_8);
            metadata.put(MetadataKeyConstants.ENCRYPTED_DATA_KEY_CONTEXT, jsonEncryptionContext);
        } catch (JsonWriter.JsonGenerationException e) {
            throw new S3EncryptionClientException("Cannot serialize encryption context to JSON.", e);
        }
        return metadata;
    }
}
