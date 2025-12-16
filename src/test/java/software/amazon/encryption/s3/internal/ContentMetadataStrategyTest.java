// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.MaterialsDescription;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ContentMetadataStrategyTest {

    private S3Client s3Client;
    private ContentMetadataDecodingStrategy decodingStrategy;
    private ContentMetadataEncodingStrategy encodingStrategy;
    private GetObjectRequest getObjectRequest;

    @BeforeEach
    public void setUp() {
        s3Client = mock(S3Client.class);
        InstructionFileConfig instructionFileConfig = InstructionFileConfig.builder()
                .instructionFileClient(s3Client)
                .build();
        decodingStrategy = new ContentMetadataDecodingStrategy(instructionFileConfig);

        InstructionFileConfig encodingInstructionFileConfig = mock(InstructionFileConfig.class);
        when(encodingInstructionFileConfig.isInstructionFilePutEnabled()).thenReturn(false);
        encodingStrategy = new ContentMetadataEncodingStrategy(encodingInstructionFileConfig);

        getObjectRequest = GetObjectRequest.builder()
                .bucket("test-bucket")
                .key("test-key")
                .build();
    }

    @Test
    public void testDetectV1Format() {
        //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //= type=test
        //# - If the metadata contains "x-amz-iv" and "x-amz-key" then the object MUST be considered as an S3EC-encrypted object using the V1 format.
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-iv", "dGVzdC1pdi0xMi1i"); // base64 of "test-iv-12-b"
        metadata.put("x-amz-key", "ZW5jcnlwdGVkLWtleS1kYXRh"); // base64 of "encrypted-key-data"
        metadata.put("x-amz-matdesc", "{}");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        ContentMetadata result = decodingStrategy.decode(getObjectRequest, response);
        assertEquals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF, result.algorithmSuite());
    }


    @Test
    public void testV3WithEncryptionContext() {
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-t" SHOULD be present for V3 format objects that use KMS Encryption Context.
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-c", "115");
        metadata.put("x-amz-3", "ZW5jcnlwdGVkLWtleS1kYXRh");
        metadata.put("x-amz-t", "{\"kms_cmk_id\":\"test-key-id\"}");
        metadata.put("x-amz-w", "12");
        metadata.put("x-amz-d", "a2V5LWNvbW1pdG1lbnQtZGF0YQ==");
        metadata.put("x-amz-i", "dGVzdC1tZXNzYWdlLWlk");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        ContentMetadata result = decodingStrategy.decode(getObjectRequest, response);
        assertEquals(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, result.algorithmSuite());
        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# The Encryption Context value MUST be used for wrapping algorithm `kms+context` or `12`.
        assertEquals(MetadataKeyConstants.V3_ALG_KMS_CONTEXT, result.encryptedDataKey().keyProviderInfo());
        assertTrue(result.encryptionContext().containsKey("kms_cmk_id"));
        assertEquals("test-key-id", result.encryptionContext().get("kms_cmk_id"));
    }

    @Test
    public void testV3AesWithMaterialDescription() {
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-m" SHOULD be present for V3 format objects that use Raw Keyring Material Description.
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-c", "115");
        metadata.put("x-amz-3", "ZW5jcnlwdGVkLWtleS1kYXRh");
        metadata.put("x-amz-m", "{\"test\":\"material-desc\"}");
        metadata.put("x-amz-w", "02");
        metadata.put("x-amz-d", "a2V5LWNvbW1pdG1lbnQtZGF0YQ==");
        metadata.put("x-amz-i", "dGVzdC1tZXNzYWdlLWlk");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        ContentMetadata result = decodingStrategy.decode(getObjectRequest, response);
        assertEquals(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, result.algorithmSuite());
        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# The Material Description MUST be used for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`).
        assertEquals(MetadataKeyConstants.V3_ALG_AES_GCM, result.encryptedDataKey().keyProviderInfo());
        assertTrue(result.materialsDescription().containsKey("test"));
        assertEquals("material-desc", result.materialsDescription().get("test"));
    }

    @Test
    public void testV3RsaWithMaterialDescription() {
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-m" SHOULD be present for V3 format objects that use Raw Keyring Material Description.
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-c", "115");
        metadata.put("x-amz-3", "ZW5jcnlwdGVkLWtleS1kYXRh");
        metadata.put("x-amz-m", "{\"test\":\"material-desc\"}");
        metadata.put("x-amz-w", "22");
        metadata.put("x-amz-d", "a2V5LWNvbW1pdG1lbnQtZGF0YQ==");
        metadata.put("x-amz-i", "dGVzdC1tZXNzYWdlLWlk");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        ContentMetadata result = decodingStrategy.decode(getObjectRequest, response);
        assertEquals(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, result.algorithmSuite());
        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# The Material Description MUST be used for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`).
        assertEquals(MetadataKeyConstants.V3_ALG_RSA_OAEP_SHA1, result.encryptedDataKey().keyProviderInfo());
        assertTrue(result.materialsDescription().containsKey("test"));
        assertEquals("material-desc", result.materialsDescription().get("test"));
    }

    @Test
    public void testV3WithoutMaterialDescriptionInMetatadata() {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-c", "115");
        metadata.put("x-amz-3", "ZW5jcnlwdGVkLWtleS1kYXRh");
        metadata.put("x-amz-w", "02");
        metadata.put("x-amz-d", "a2V5LWNvbW1pdG1lbnQtZGF0YQ==");
        metadata.put("x-amz-i", "dGVzdC1tZXNzYWdlLWlk");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        ContentMetadata result = decodingStrategy.decode(getObjectRequest, response);
        assertEquals(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, result.algorithmSuite());
        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# If the mapkey x-amz-m is not present, the default Material Description value MUST be set to an empty map (`{}`).
        assertTrue(result.materialsDescription().isEmpty());
        assertEquals(MetadataKeyConstants.decompressWrappingAlgorithm("02"),
                result.encryptedDataKey().keyProviderInfo());
    }

    @Test
    public void testRangedGetV3() {
        //= specification/s3-encryption/decryption.md#ranged-gets
        //= type=test
        //# If the object was encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, then
        //# ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY MUST be used to decrypt the range of the object.
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-c", "115");
        metadata.put("x-amz-3", "ZW5jcnlwdGVkLWtleS1kYXRh");
        metadata.put("x-amz-w", "12");
        metadata.put("x-amz-d", "a2V5LWNvbW1pdG1lbnQtZGF0YQ==");
        metadata.put("x-amz-i", "dGVzdC1tZXNzYWdlLWlk");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .contentRange("bytes 0-1023/2048")
                .build();

        ContentMetadata result = decodingStrategy.decode(getObjectRequest, response);
        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# If the mapkey x-amz-t is not present, the default Material Description value MUST be set to an empty map (`{}`).
        assertTrue(result.materialsDescription().isEmpty());
        assertEquals(AlgorithmSuite.ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY, result.algorithmSuite());
    }

    @Test
    public void testRangedGetV2() {
        //= specification/s3-encryption/decryption.md#ranged-gets
        //= type=test
        //# If the object was encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF, then
        //# ALG_AES_256_CTR_IV16_TAG16_NO_KDF MUST be used to decrypt the range of the object.
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-iv", "dGVzdC1pdi0xMi1i");
        metadata.put("x-amz-key-v2", "ZW5jcnlwdGVkLWtleS1kYXRh");
        metadata.put("x-amz-matdesc", "{}");
        metadata.put("x-amz-wrap-alg", "AES/GCM");
        metadata.put("x-amz-cek-alg", "AES/GCM/NoPadding");
        metadata.put("x-amz-tag-len", "128");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .contentRange("bytes 0-1023/2048")
                .build();

        ContentMetadata result = decodingStrategy.decode(getObjectRequest, response);
        assertEquals(AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF, result.algorithmSuite());
    }

    @Test
    public void testV1LegacyInferAESFromCiphertextLength() {
        // Test legacy V1 behavior where algorithm is inferred from ciphertext length
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-iv", "dGVzdC1pdi0xMi1i");
        metadata.put("x-amz-key", "c2hvcnQtYWVzLWtleQ=="); // Short key (< 48 bytes) should infer AES
        metadata.put("x-amz-matdesc", "{}");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        ContentMetadata result = decodingStrategy.decode(getObjectRequest, response);
        assertEquals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF, result.algorithmSuite());
        assertEquals("AES", result.encryptedDataKey().keyProviderInfo());
    }

    @Test
    public void testV1LegacyInferRSAFromCiphertextLength() {
        // Test legacy V1 behavior where algorithm is inferred from ciphertext length
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-iv", "dGVzdC1pdi0xMi1i");
        // Long key (> 48 bytes) should infer RSA
        metadata.put("x-amz-key", "dGhpcy1pcy1hLXZlcnktbG9uZy1yc2Eta2V5LXRoYXQtZXhjZWVkcy00OC1ieXRlcy1hbmQtc2hvdWxkLWJlLWluZmVycmVkLWFzLXJzYQ==");
        metadata.put("x-amz-matdesc", "{}");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        ContentMetadata result = decodingStrategy.decode(getObjectRequest, response);
        assertEquals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF, result.algorithmSuite());
        assertEquals("RSA", result.encryptedDataKey().keyProviderInfo());
    }

    @Test
    public void testUnknownContentEncryptionAlgorithmV3() {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-c", "999"); // Unknown algorithm
        metadata.put("x-amz-3", "ZW5jcnlwdGVkLWtleS1kYXRh");
        metadata.put("x-amz-w", "12");
        metadata.put("x-amz-d", "a2V5LWNvbW1pdG1lbnQtZGF0YQ==");
        metadata.put("x-amz-i", "dGVzdC1tZXNzYWdlLWlk");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> decodingStrategy.decode(getObjectRequest, response));
        assertTrue(exception.getMessage().contains("Unknown content encryption algorithm for V3 message format"));
    }

    @Test
    public void testUnknownContentEncryptionAlgorithmV2() {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-iv", "dGVzdC1pdi0xMi1i");
        metadata.put("x-amz-key-v2", "ZW5jcnlwdGVkLWtleS1kYXRh");
        metadata.put("x-amz-matdesc", "{}");
        metadata.put("x-amz-wrap-alg", "AES/GCM");
        metadata.put("x-amz-cek-alg", "UnknownAlgorithm");
        metadata.put("x-amz-tag-len", "128");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> decodingStrategy.decode(getObjectRequest, response));
        assertTrue(exception.getMessage().contains("Unknown content encryption algorithm for V2 message format"));
    }

    @Test
    public void testMissingKeysV3InstructionFile() {
        Map<String, String> objectMetadata = new HashMap<>();
        objectMetadata.put("x-amz-c", "115");
        objectMetadata.put("x-amz-d", "a2V5LWNvbW1pdG1lbnQtZGF0YQ==");
        objectMetadata.put("x-amz-i", "dGVzdC1tZXNzYWdlLWlk");

        Map<String, String> instructionMetadata = new HashMap<>();
        // Remove the v3 format mapkey from instruction file
        // instructionMetadata.put("x-amz-3", "ZW5jcnlwdGVkLWtleS1kYXRh");
        instructionMetadata.put("x-amz-m", "{\"test-instruction\":\"material-desc-instruction\"}");
        instructionMetadata.put("x-amz-w", "02");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(objectMetadata)
                .build();

        // Mock Instruction File Object
        String instructionContent = metadataToString(instructionMetadata);
        ResponseInputStream<GetObjectResponse> responseInputStream = new ResponseInputStream<>(GetObjectResponse.builder().build(), new ByteArrayInputStream(instructionContent.getBytes()));
        when(s3Client.getObject(any(GetObjectRequest.class))).thenReturn(responseInputStream);

        //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //= type=test
        //# In general, if there is any deviation from the above format, with the exception of additional unrelated mapkeys, then the S3EC SHOULD throw an exception.
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> decodingStrategy.decode(getObjectRequest, response));
        assertTrue(exception.getMessage().contains("Content metadata is tampered, required metadata to decrypt the object are missing"));
    }

    @Test
    public void testMissingKeysV3() {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-c", "999"); // Unknown algorithm
        metadata.put("x-amz-3", "ZW5jcnlwdGVkLWtleS1kYXRh");
        // Remove v2 format mapkey from metadata
        // metadata.put("x-amz-w", "12");
        metadata.put("x-amz-d", "a2V5LWNvbW1pdG1lbnQtZGF0YQ==");
        metadata.put("x-amz-i", "dGVzdC1tZXNzYWdlLWlk");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //= type=test
        //# In general, if there is any deviation from the above format, with the exception of additional unrelated mapkeys, then the S3EC SHOULD throw an exception.
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> decodingStrategy.decode(getObjectRequest, response));
        assertTrue(exception.getMessage().contains("Content metadata is tampered, required metadata to decrypt the object are missing"));
    }

    @Test
    public void testMissingKeysV2InstructionFile() {
        Map<String, String> instructionMetadata = new HashMap<>();
        instructionMetadata.put("x-amz-iv", "dGVzdC1pdi0xMi1i");
        instructionMetadata.put("x-amz-key-v2", "ZW5jcnlwdGVkLWtleS1kYXRh");
        instructionMetadata.put("x-amz-matdesc", "{}");
        // Remove v2 format mapkey from instruction Fele Metadata
        // instructionMetadata.put("x-amz-wrap-alg", "AES/GCM");
        instructionMetadata.put("x-amz-cek-alg", "UnknownAlgorithm");
        instructionMetadata.put("x-amz-tag-len", "128");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(Collections.EMPTY_MAP)
                .build();

        // Mock Instruction File Object
        String instructionContent = metadataToString(instructionMetadata);
        ResponseInputStream<GetObjectResponse> responseInputStream = new ResponseInputStream<>(GetObjectResponse.builder().build(), new ByteArrayInputStream(instructionContent.getBytes()));
        when(s3Client.getObject(any(GetObjectRequest.class))).thenReturn(responseInputStream);

        //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //= type=test
        //# In general, if there is any deviation from the above format, with the exception of additional unrelated mapkeys, then the S3EC SHOULD throw an exception.
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> decodingStrategy.decode(getObjectRequest, response));
        assertTrue(exception.getMessage().contains("Content metadata is tampered, required metadata to decrypt the object are missing"));
    }

    @Test
    public void testMissingKeysV2() {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-iv", "dGVzdC1pdi0xMi1i");
        metadata.put("x-amz-key-v2", "ZW5jcnlwdGVkLWtleS1kYXRh");
        metadata.put("x-amz-matdesc", "{}");
        // Remove v2 format mapkey from metadata
        // metadata.put("x-amz-wrap-alg", "AES/GCM");
        metadata.put("x-amz-cek-alg", "UnknownAlgorithm");
        metadata.put("x-amz-tag-len", "128");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //= type=test
        //# In general, if there is any deviation from the above format, with the exception of additional unrelated mapkeys, then the S3EC SHOULD throw an exception.
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> decodingStrategy.decode(getObjectRequest, response));
        assertTrue(exception.getMessage().contains("Content metadata is tampered, required metadata to decrypt the object are missing"));
    }

    @Test
    public void testMissingKeysV1() {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-iv", "dGVzdC1pdi0xMi1i");
        metadata.put("x-amz-key", "ZW5jcnlwdGVkLWtleS1kYXRh");
        // Remove v1 format mapkey from metadata
        // metadata.put("x-amz-matdesc", "{}");

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //= type=test
        //# In general, if there is any deviation from the above format, with the exception of additional unrelated mapkeys, then the S3EC SHOULD throw an exception.
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> decodingStrategy.decode(getObjectRequest, response));
        assertTrue(exception.getMessage().contains("Content metadata is tampered, required metadata to decrypt the object are missing"));
    }

    @Test
    public void testExclusiveKeysCollision() {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-iv", "dGVzdC1pdi0xMi1i");
        metadata.put("x-amz-key-v2", "ZW5jcnlwdGVkLWtleS1kYXRh");
        metadata.put("x-amz-matdesc", "{}");
        metadata.put("x-amz-wrap-alg", "AES/GCM");
        metadata.put("x-amz-cek-alg", "UnknownAlgorithm");
        metadata.put("x-amz-tag-len", "128");
        // Add v1 format exclusive key
        metadata.put("x-amz-key", "dGaskjbdviqebfviVkLWtleS1kYXRh");


        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //= type=test
        //# If there are multiple mapkeys which are meant to be exclusive, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> decodingStrategy.decode(getObjectRequest, response));
        assertTrue(exception.getMessage().contains("Content metadata is tampered, required metadata to decrypt the object are missing"));
    }

    @Test
    public void testTagLengthValidationV2() {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("x-amz-iv", "dGVzdC1pdi0xMi1i");
        metadata.put("x-amz-key-v2", "ZW5jcnlwdGVkLWtleS1kYXRh");
        metadata.put("x-amz-matdesc", "{}");
        metadata.put("x-amz-wrap-alg", "AES/GCM");
        metadata.put("x-amz-cek-alg", "AES/GCM/NoPadding");
        metadata.put("x-amz-tag-len", "96"); // Wrong tag length

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(metadata)
                .build();

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> decodingStrategy.decode(getObjectRequest, response));
        assertTrue(exception.getMessage().contains("Expected tag length (bits) of:"));
    }

    static Stream<Arguments> provideMetadataFormatDetection() {
        Map<String, String> v1Metadata = new HashMap<>();
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-iv" MUST be present for V1 format objects.
        v1Metadata.put("x-amz-iv", "iv");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-key" MUST be present for V1 format objects.
        v1Metadata.put("x-amz-key", "key");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-matdesc" MUST be present for V1 format objects.
        v1Metadata.put("x-amz-matdesc", "{}");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-unencrypted-content-length" SHOULD be present for V1 format objects.
        v1Metadata.put("x-amz-unencrypted-content-length", "1024");
        v1Metadata.put("x-amz-wrap-alg", "AES");
        v1Metadata.put("x-amz-cek-alg", "AES/CBC/PKCS5Padding");
        v1Metadata.put("x-amz-tag-len", "128");

        Map<String, String> v2Metadata = new HashMap<>();
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-iv" MUST be present for V2 format objects.
        v2Metadata.put("x-amz-iv", "iv");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-key-v2" MUST be present for V2 format objects.
        v2Metadata.put("x-amz-key-v2", "key");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-matdesc" MUST be present for V2 format objects.
        v2Metadata.put("x-amz-matdesc", "{}");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-wrap-alg" MUST be present for V2 format objects.
        v2Metadata.put("x-amz-wrap-alg", "AES/GCM");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-cek-alg" MUST be present for V2 format objects.
        v2Metadata.put("x-amz-cek-alg", "AES/GCM/NoPadding");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-tag-len" MUST be present for V2 format objects.
        v2Metadata.put("x-amz-tag-len", "128");

        Map<String, String> v2CbcMetadata = new HashMap<>();
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-iv" MUST be present for V2 format objects.
        v2CbcMetadata.put("x-amz-iv", "iv");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-key-v2" MUST be present for V2 format objects.
        v2CbcMetadata.put("x-amz-key-v2", "key");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-matdesc" MUST be present for V2 format objects.
        v2CbcMetadata.put("x-amz-matdesc", "{}");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-wrap-alg" MUST be present for V2 format objects.
        v2CbcMetadata.put("x-amz-wrap-alg", "AES");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-cek-alg" MUST be present for V2 format objects.
        v2CbcMetadata.put("x-amz-cek-alg", "AES/CBC/PKCS5Padding");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-tag-len" MUST be present for V2 format objects.
        v2CbcMetadata.put("x-amz-tag-len", "128");


        Map<String, String> v3Metadata = new HashMap<>();
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-3" MUST be present for V3 format objects.
        v3Metadata.put("x-amz-3", "key");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-d" MUST be present for V3 format objects.
        v3Metadata.put("x-amz-d", "commitment");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-i" MUST be present for V3 format objects.
        v3Metadata.put("x-amz-i", "iv");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-c" MUST be present for V3 format objects.
        v3Metadata.put("x-amz-c", "115");
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-w" MUST be present for V3 format objects.
        v3Metadata.put("x-amz-w", "02");

        return Stream.of(
                //= specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
                //= type=test
                //# Objects encrypted with ALG_AES_256_CBC_IV16_NO_KDF MAY use either the V1 or V2 message format version.
                //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
                //= type=test
                //# - If the metadata contains "x-amz-iv" and "x-amz-key" then the object MUST be considered as an S3EC-encrypted object using the V1 format.
                Arguments.of(v1Metadata, "V1", AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF),
                //= specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
                //= type=test
                //# Objects encrypted with ALG_AES_256_CBC_IV16_NO_KDF MAY use either the V1 or V2 message format version.
                //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
                //= type=test
                //# - If the metadata contains "x-amz-iv" and "x-amz-metadata-x-amz-key-v2" then the object MUST be considered as an S3EC-encrypted object using the V2 format.
                Arguments.of(v2CbcMetadata, "V2", AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF),
                //= specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
                //= type=test
                //# Objects encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF MUST use the V2 message format version only.
                //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
                //= type=test
                //# - If the metadata contains "x-amz-iv" and "x-amz-metadata-x-amz-key-v2" then the object MUST be considered as an S3EC-encrypted object using the V2 format.
                Arguments.of(v2Metadata, "V2", AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF),
                //= specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
                //= type=test
                //# Objects encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY MUST use the V3 message format version only.
                //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
                //= type=test
                //# - If the metadata contains "x-amz-3" and "x-amz-d" and "x-amz-i" then the object MUST be considered an S3EC-encrypted object using the V3 format.
                Arguments.of(v3Metadata, "V3", AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
        );
    }

    @ParameterizedTest
    @MethodSource("provideMetadataFormatDetection")
    public void testMetadataFormatDetection(Map<String, String> metadata, String expectedFormat, AlgorithmSuite expectedAlgorithm) {
        // This test verifies that the format detection logic works correctly
        // The actual format detection is implicit in the decode method behavior
        Map<String, String> testMetadata = new HashMap<>(metadata);
        GetObjectResponse.Builder responseBuilder = GetObjectResponse.builder();

        GetObjectResponse response = responseBuilder.metadata(testMetadata).build();

        // Should not throw exception for valid formats
        assertDoesNotThrow(() -> {
            ContentMetadata contentMetadata = decodingStrategy.decode(getObjectRequest, response);
            assertEquals(expectedAlgorithm, contentMetadata.algorithmSuite());
        });
    }

    // ========== ENCODING TESTS ==========

    @Test
    public void testEncodeMetadataV2GCM() {
        // Test V2 metadata encoding similar to Go's TestEncodeMetaV2
        EncryptedDataKey edk = EncryptedDataKey.builder()
                .encryptedDataKey("encrypted-key-data".getBytes(StandardCharsets.UTF_8))
                .keyProviderId("test-provider")
                .keyProviderInfo("kms+context")
                .build();

        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("aws:x-amz-cek-alg", "AES/GCM/NoPadding")
                .put("custom", "value")
                .build();

        EncryptionMaterials materials = EncryptionMaterials.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .encryptedDataKeys(java.util.Collections.singletonList(edk))
                .materialsDescription(materialsDescription)
                .build();

        byte[] iv = "test-iv-12-b".getBytes(StandardCharsets.UTF_8);

        PutObjectRequest originalRequest = PutObjectRequest.builder()
                .bucket("test-bucket")
                .key("test-key")
                .build();

        PutObjectRequest result = encodingStrategy.encodeMetadata(materials, iv, originalRequest);

        // Verify V2 format metadata
        Map<String, String> metadata = result.metadata();
        assertNotNull(metadata);

        assertEquals(Base64.getEncoder().encodeToString(edk.encryptedDatakey()),
                metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2));
        assertEquals(Base64.getEncoder().encodeToString(iv),
                metadata.get(MetadataKeyConstants.CONTENT_IV));
        assertEquals("AES/GCM/NoPadding",
                metadata.get(MetadataKeyConstants.CONTENT_CIPHER));
        assertEquals("128",
                metadata.get(MetadataKeyConstants.CONTENT_CIPHER_TAG_LENGTH));
        assertEquals("kms+context",
                metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM));

        // Verify material description is JSON encoded
        String matDesc = metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_MATDESC_OR_EC);
        assertNotNull(matDesc);
        assertTrue(matDesc.contains("aws:x-amz-cek-alg"));
        assertTrue(matDesc.contains("AES/GCM/NoPadding"));
        assertTrue(matDesc.contains("custom"));
        assertTrue(matDesc.contains("value"));
    }

    @Test
    public void testEncodeMetaV2WithEmptyMaterialDescription() {
        EncryptedDataKey edk = EncryptedDataKey.builder()
                .encryptedDataKey("encrypted-key-data".getBytes(StandardCharsets.UTF_8))
                .keyProviderId("test-provider")
                .keyProviderInfo("kms")
                .build();

        EncryptionMaterials materials = EncryptionMaterials.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .encryptedDataKeys(Collections.singletonList(edk))
                .materialsDescription(MaterialsDescription.builder().build())
                .build();

        byte[] iv = "test-iv-12-b".getBytes(StandardCharsets.UTF_8);

        PutObjectRequest originalRequest = PutObjectRequest.builder()
                .bucket("test-bucket")
                .key("test-key")
                .build();

        PutObjectRequest result = encodingStrategy.encodeMetadata(materials, iv, originalRequest);

        Map<String, String> metadata = result.metadata();
        String matDesc = metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_MATDESC_OR_EC);
        assertEquals("{}", matDesc);
    }

    @Test
    public void testDecodeMetadataV3GCMFromInstructionFile() {
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-m" SHOULD be present for V3 format objects that use Raw Keyring Material Description.
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-c" and its value in the Object Metadata when writing with an Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-d" and its value in the Object Metadata when writing with an Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-i" and its value in the Object Metadata when writing with an Instruction File.
        Map<String, String> objectMetadata = new HashMap<>();
        objectMetadata.put("x-amz-c", "115");
        objectMetadata.put("x-amz-d", "a2V5LWNvbW1pdG1lbnQtZGF0YQ==");
        objectMetadata.put("x-amz-i", "dGVzdC1tZXNzYWdlLWlk");

        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST NOT store the mapkey "x-amz-c" and its value in the Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST NOT store the mapkey "x-amz-d" and its value in the Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST NOT store the mapkey "x-amz-i" and its value in the Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-3" and its value in the Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-w" and its value in the Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-m" and its value (when present in the content metadata) in the Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-t" and its value (when present in the content metadata) in the Instruction File.
        Map<String, String> instructionMetadata = new HashMap<>();
        instructionMetadata.put("x-amz-3", "ZW5jcnlwdGVkLWtleS1kYXRh");
        instructionMetadata.put("x-amz-m", "{\"test-instruction\":\"material-desc-instruction\"}");
        instructionMetadata.put("x-amz-w", "02");

        String instructionContent = metadataToString(instructionMetadata);

        GetObjectResponse response = GetObjectResponse.builder()
                .metadata(objectMetadata)
                .build();


        ResponseInputStream responseInputStream = new ResponseInputStream<>(GetObjectResponse.builder().build(), new ByteArrayInputStream(instructionContent.getBytes()));

        when(s3Client.getObject(any(GetObjectRequest.class))).thenReturn(responseInputStream);

        ContentMetadata result = decodingStrategy.decode(getObjectRequest, response);
        assertEquals(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, result.algorithmSuite());
        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# The Material Description MUST be used for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`).
        assertEquals(MetadataKeyConstants.V3_ALG_AES_GCM, result.encryptedDataKey().keyProviderInfo());
        assertTrue(result.materialsDescription().containsKey("test-instruction"));
        assertEquals("material-desc-instruction", result.materialsDescription().get("test-instruction"));
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

    @Test
    public void testEncodeMetaV3WithAESGCM() {
        // Test V3 encoding with AES/GCM wrapping algorithm
        EncryptedDataKey edk = EncryptedDataKey.builder()
                .encryptedDataKey("encrypted-key-data".getBytes(StandardCharsets.UTF_8))
                .keyProviderId("test-provider")
                .keyProviderInfo("AES/GCM")
                .build();

        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("test", "material-desc")
                .put("custom", "value")
                .build();

        EncryptionMaterials materials = EncryptionMaterials.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                .encryptedDataKeys(java.util.Collections.singletonList(edk))
                .materialsDescription(materialsDescription)
                .build();

        // Key Commitment is set during Cipher Initialization
        materials.setKeyCommitment("key-commitment-data".getBytes(StandardCharsets.UTF_8));

        byte[] iv = "test-iv-28-bytes-long-1234567890".getBytes(StandardCharsets.UTF_8);

        PutObjectRequest originalRequest = PutObjectRequest.builder()
                .bucket("test-bucket")
                .key("test-key")
                .build();

        PutObjectRequest result = encodingStrategy.encodeMetadata(materials, iv, originalRequest);

        // Verify V3 format metadata
        Map<String, String> metadata = result.metadata();
        assertNotNull(metadata);

        assertEquals(Base64.getEncoder().encodeToString(edk.encryptedDatakey()),
                metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V3));
        assertEquals(Base64.getEncoder().encodeToString(iv),
                metadata.get(MetadataKeyConstants.MESSAGE_ID_V3));
        assertEquals("115",
                metadata.get(MetadataKeyConstants.CONTENT_CIPHER_V3));
        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# The Material Description MUST be used for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`).
        assertEquals("02", // Compressed AES/GCM
                metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM_V3));
        assertEquals(Base64.getEncoder().encodeToString(materials.getKeyCommitment()),
                metadata.get(MetadataKeyConstants.KEY_COMMITMENT_V3));

        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-m" SHOULD be present for V3 format objects that use Raw Keyring Material Description.
        String matDesc = metadata.get(MetadataKeyConstants.MAT_DESC_V3);
        assertNotNull(matDesc);
        assertTrue(matDesc.contains("test"));
        assertTrue(matDesc.contains("material-desc"));
        assertTrue(matDesc.contains("custom"));
        assertTrue(matDesc.contains("value"));
    }

    @Test
    public void testEncodeMetaV3WithKMSContext() {
        // Test V3 encoding with kms+context wrapping algorithm
        EncryptedDataKey edk = EncryptedDataKey.builder()
                .encryptedDataKey("encrypted-key-data".getBytes(StandardCharsets.UTF_8))
                .keyProviderId("test-provider")
                .keyProviderInfo("kms+context")
                .build();

        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("kms_cmk_id", "test-key-id");
        encryptionContext.put("custom", "value");

        EncryptionMaterials materials = EncryptionMaterials.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                .encryptedDataKeys(java.util.Collections.singletonList(edk))
                .encryptionContext(encryptionContext)
                .build();

        materials.setKeyCommitment("key-commitment-data".getBytes(StandardCharsets.UTF_8));

        byte[] iv = "test-iv-28-bytes-long-1234567890".getBytes(StandardCharsets.UTF_8);

        PutObjectRequest originalRequest = PutObjectRequest.builder()
                .bucket("test-bucket")
                .key("test-key")
                .build();

        PutObjectRequest result = encodingStrategy.encodeMetadata(materials, iv, originalRequest);

        Map<String, String> metadata = result.metadata();
        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# The Encryption Context value MUST be used for wrapping algorithm `kms+context` or `12`.
        assertEquals("12", // Compressed kms+context
                metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM_V3));

        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-t" SHOULD be present for V3 format objects that use KMS Encryption Context.
        String encCtx = metadata.get(MetadataKeyConstants.ENCRYPTION_CONTEXT_V3);
        assertNotNull(encCtx);
        assertTrue(encCtx.contains("kms_cmk_id"));
        assertTrue(encCtx.contains("test-key-id"));
        assertTrue(encCtx.contains("custom"));
        assertTrue(encCtx.contains("value"));
    }

    @Test
    public void testEncodeMetaV3WithRSAOAEP() {
        // Test V3 encoding with RSA-OAEP-SHA1 wrapping algorithm
        EncryptedDataKey edk = EncryptedDataKey.builder()
                .encryptedDataKey("encrypted-key-data".getBytes(StandardCharsets.UTF_8))
                .keyProviderId("test-provider")
                .keyProviderInfo("RSA-OAEP-SHA1")
                .build();

        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("rsa", "material-desc")
                .build();

        EncryptionMaterials materials = EncryptionMaterials.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                .encryptedDataKeys(java.util.Collections.singletonList(edk))
                .materialsDescription(materialsDescription)
                .build();

        materials.setKeyCommitment("key-commitment-data".getBytes(StandardCharsets.UTF_8));

        byte[] iv = "test-iv-28-bytes-long-1234567890".getBytes(StandardCharsets.UTF_8);

        PutObjectRequest originalRequest = PutObjectRequest.builder()
                .bucket("test-bucket")
                .key("test-key")
                .build();

        PutObjectRequest result = encodingStrategy.encodeMetadata(materials, iv, originalRequest);

        Map<String, String> metadata = result.metadata();
        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# The Material Description MUST be used for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`).
        assertEquals("22", // Compressed RSA-OAEP-SHA1
                metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM_V3));

        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# - The mapkey "x-amz-m" SHOULD be present for V3 format objects that use Raw Keyring Material Description.
        String matDesc = metadata.get(MetadataKeyConstants.MAT_DESC_V3);
        assertNotNull(matDesc);
        assertTrue(matDesc.contains("rsa"));
        assertTrue(matDesc.contains("material-desc"));
    }
}
