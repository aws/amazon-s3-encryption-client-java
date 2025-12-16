// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import static software.amazon.encryption.s3.S3EncryptionClientUtilities.DEFAULT_INSTRUCTION_FILE_SUFFIX;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import software.amazon.awssdk.protocols.jsoncore.JsonWriter;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

public class ContentMetadataEncodingStrategy {

    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private final InstructionFileConfig _instructionFileConfig;

    public ContentMetadataEncodingStrategy(InstructionFileConfig instructionFileConfig) {
        _instructionFileConfig = instructionFileConfig;
    }

    public PutObjectRequest encodeMetadata(EncryptionMaterials materials, byte[] iv, PutObjectRequest putObjectRequest) {
        return encodeMetadata(materials, iv, putObjectRequest, DEFAULT_INSTRUCTION_FILE_SUFFIX);
    }

    public PutObjectRequest encodeMetadata(EncryptionMaterials materials, byte[] iv, PutObjectRequest putObjectRequest, String instructionFileSuffix) {
        //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //# The S3EC MUST support writing some or all (depending on format) content metadata to an Instruction File.
        if (_instructionFileConfig.isInstructionFilePutEnabled()) {
            //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //# The content metadata stored in the Instruction File MUST be serialized to a JSON string.
            String metadataString;
            Map<String, String> objectMetadata;
            if (materials.algorithmSuite().isCommitting()) {
                // TODO: Should throw an exception for Commiting Alg
                throw new S3EncryptionClientException("This version of S3EC does not support encryption with committing algorithm suite: " + materials.algorithmSuite());
            } else {
                metadataString = metadataToStringForV1V2InstructionFile(materials, iv);
                objectMetadata = putObjectRequest.metadata();
            }
            //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //# The serialized JSON string MUST be the only contents of the Instruction File.
            _instructionFileConfig.putInstructionFile(putObjectRequest, metadataString, instructionFileSuffix);
            return putObjectRequest.toBuilder()
                    .metadata(objectMetadata)
                    .build();
        } else {
            //= specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
            //# By default, the S3EC MUST store content metadata in the S3 Object Metadata.
            Map<String, String> newMetadata = addMetadataToMap(putObjectRequest.metadata(), materials, iv);
            return putObjectRequest.toBuilder()
              .metadata(newMetadata)
              .build();
        }
    }

    // TODO: refactor shared code
    public CreateMultipartUploadRequest encodeMetadata(EncryptionMaterials materials, byte[] iv, CreateMultipartUploadRequest createMultipartUploadRequest) {
        if(_instructionFileConfig.isInstructionFilePutEnabled()) {
            //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
            //# The content metadata stored in the Instruction File MUST be serialized to a JSON string.
            String metadataString;
            Map<String, String> objectMetadata;
            if (materials.algorithmSuite().isCommitting()) {
                // TODO: Should throw an exception for Commiting Alg
                throw new S3EncryptionClientException("This version of S3EC does not support encryption with committing algorithm suite: " + materials.algorithmSuite());
            } else {
                metadataString = metadataToStringForV1V2InstructionFile(materials, iv);
                objectMetadata = createMultipartUploadRequest.metadata();
            }
            PutObjectRequest putObjectRequest = ConvertSDKRequests.convertRequest(createMultipartUploadRequest);
            _instructionFileConfig.putInstructionFile(putObjectRequest, metadataString);
            return createMultipartUploadRequest.toBuilder()
                    .metadata(objectMetadata).build();
        } else {
            Map<String, String> newMetadata = addMetadataToMap(createMultipartUploadRequest.metadata(), materials, iv);
            return createMultipartUploadRequest.toBuilder()
                    .metadata(newMetadata)
                    .build();
        }
    }

    //= specification/s3-encryption/data-format/metadata-strategy.md#v1-v2-instruction-files
    //# In the V1/V2 message format, all of the content metadata MUST be stored in the Instruction File.
    private String metadataToStringForV1V2InstructionFile(EncryptionMaterials materials, byte[] iv) {
        final Map<String, String> metadataMap = addMetadataToMap(new HashMap<>(), materials, iv);
        return metadataToString(metadataMap);
    }

    private String metadataToString(Map<String, String> metadataMap) {
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
        if (materials.algorithmSuite().isCommitting()) {
            // TODO: Should throw an exception for Commiting Alg
            throw new S3EncryptionClientException("This version of S3EC does not support encryption with committing algorithm suite: " + materials.algorithmSuite());
        }
        Map<String, String> metadata = new HashMap<>(map);
        EncryptedDataKey edk = materials.encryptedDataKeys().get(0);
        metadata.put(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2, ENCODER.encodeToString(edk.encryptedDatakey()));
        metadata.put(MetadataKeyConstants.CONTENT_IV, ENCODER.encodeToString(iv));
        metadata.put(MetadataKeyConstants.CONTENT_CIPHER, materials.algorithmSuite().cipherName());
        metadata.put(MetadataKeyConstants.CONTENT_CIPHER_TAG_LENGTH, Integer.toString(materials.algorithmSuite().cipherTagLengthBits()));
        metadata.put(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM, edk.keyProviderInfo());

        try (JsonWriter jsonWriter = JsonWriter.create()) {
            jsonWriter.writeStartObject();
            if (!materials.encryptionContext().isEmpty() && materials.materialsDescription().isEmpty()) {
                for (Map.Entry<String, String> entry : materials.encryptionContext().entrySet()) {
                    jsonWriter.writeFieldName(entry.getKey()).writeValue(entry.getValue());
                }
            } else if (materials.encryptionContext().isEmpty() && !materials.materialsDescription().isEmpty()) {
                for (Map.Entry<String, String> entry : materials.materialsDescription().entrySet()) {
                        jsonWriter.writeFieldName(entry.getKey()).writeValue(entry.getValue());
                }
            }
            jsonWriter.writeEndObject();
            String jsonEncryptionContext = new String(jsonWriter.getBytes(), StandardCharsets.UTF_8);
            metadata.put(MetadataKeyConstants.ENCRYPTED_DATA_KEY_MATDESC_OR_EC, jsonEncryptionContext);
        } catch (JsonWriter.JsonGenerationException e) {
            throw new S3EncryptionClientException("Cannot serialize encryption context to JSON.", e);
        }
        return metadata;
    }
}
