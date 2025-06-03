// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
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

public class ContentMetadataEncodingStrategy {

    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private final InstructionFileConfig _instructionFileConfig;

    public ContentMetadataEncodingStrategy(InstructionFileConfig instructionFileConfig) {
        _instructionFileConfig = instructionFileConfig;
    }

    public PutObjectRequest encodeMetadata(EncryptionMaterials materials, byte[] iv, PutObjectRequest putObjectRequest) {
        if (_instructionFileConfig.isInstructionFilePutEnabled()) {
            final String metadataString = metadataToString(materials, iv);
            _instructionFileConfig.putInstructionFile(putObjectRequest, metadataString);
            // the original request object is returned as-is
            return putObjectRequest;
        } else {
            Map<String, String> newMetadata = addMetadataToMap(putObjectRequest.metadata(), materials, iv);
            return putObjectRequest.toBuilder()
                    .metadata(newMetadata)
                    .build();
        }
    }

    public CreateMultipartUploadRequest encodeMetadata(EncryptionMaterials materials, byte[] iv, CreateMultipartUploadRequest createMultipartUploadRequest) {
        if(_instructionFileConfig.isInstructionFilePutEnabled()) {
            final String metadataString = metadataToString(materials, iv);
            PutObjectRequest putObjectRequest = ConvertSDKRequests.convertRequest(createMultipartUploadRequest);
            _instructionFileConfig.putInstructionFile(putObjectRequest, metadataString);
            // the original request object is returned as-is
            return createMultipartUploadRequest;
        } else {
            Map<String, String> newMetadata = addMetadataToMap(createMultipartUploadRequest.metadata(), materials, iv);
            return createMultipartUploadRequest.toBuilder()
                    .metadata(newMetadata)
                    .build();
        }
    }
    private String metadataToString(EncryptionMaterials materials, byte[] iv) {
        // this is just the metadata map serialized as JSON
        // so first get the Map
        final Map<String, String> metadataMap = addMetadataToMap(new HashMap<>(), materials, iv);
        // then serialize it
        try (JsonWriter jsonWriter = JsonWriter.create()) {
            jsonWriter.writeStartObject();
            for (Map.Entry<String, String> entry : metadataMap.entrySet()) {
                jsonWriter.writeFieldName(entry.getKey()).writeValue(entry.getValue());
            }
            jsonWriter.writeEndObject();

            return new String(jsonWriter.getBytes(), StandardCharsets.UTF_8);
        } catch (JsonWriter.JsonGenerationException e) {
            throw new S3EncryptionClientException("Cannot serialize materials to JSON.", e);
        }
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
