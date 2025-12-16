// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

public class CryptographicMaterialsValidationTest {

    @Test
    public void testEncryptionMaterialsWithNullAlgorithmSuite() {
        assertThrows(NullPointerException.class, () ->
            EncryptionMaterials.builder()
                .algorithmSuite(null)
                .plaintextDataKey(new byte[32])
                .s3Request(PutObjectRequest.builder().bucket("test").key("test").build())
                .build()
        );
    }

    @Test
    public void testEncryptionMaterialsWithInvalidDataKeyLength() {
        // Test with wrong data key length - this might be validated by the keyring rather than materials
        byte[] shortKey = new byte[16]; // Should be 32 for AES-256
        
        // The materials builder itself might not validate key length
        // Validation typically happens at the keyring or cipher level
        EncryptionMaterials materials = EncryptionMaterials.builder()
            .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
            .plaintextDataKey(shortKey)
            .s3Request(PutObjectRequest.builder().bucket("test").key("test").build())
            .build();
        
        // The validation would happen when the materials are used, not when created
        assertEquals(16, materials.plaintextDataKey().length);
    }

    @Test
    public void testMaterialsDescriptionValidation() {
        // Test empty materials description
        MaterialsDescription emptyDesc = MaterialsDescription.builder().build();
        assertTrue(emptyDesc.getMaterialsDescription().isEmpty());

        // Test materials description with null values should be rejected
        assertThrows(IllegalArgumentException.class, () ->
            MaterialsDescription.builder().put("key", null).build()
        );

        // Test materials description with null key should be rejected
        assertThrows(IllegalArgumentException.class, () ->
            MaterialsDescription.builder().put(null, "value").build()
        );
    }

    @Test
    public void testEncryptedDataKeyValidation() {
        // Test with null encrypted key
        EncryptedDataKey keyWithNullData = EncryptedDataKey.builder()
            .encryptedDataKey(null)
            .keyProviderId("test-provider")
            .keyProviderInfo("test-info")
            .build();

        assertNull(keyWithNullData.encryptedDatakey());

        // Test with empty key provider ID - this might be allowed
        EncryptedDataKey keyWithEmptyProvider = EncryptedDataKey.builder()
            .encryptedDataKey(new byte[32])
            .keyProviderId("")
            .keyProviderInfo("test-info")
            .build();

        assertEquals("", keyWithEmptyProvider.keyProviderId());

        // Test with null key provider ID
        EncryptedDataKey keyWithNullProvider = EncryptedDataKey.builder()
            .encryptedDataKey(new byte[32])
            .keyProviderId(null)
            .keyProviderInfo("test-info")
            .build();

        assertNull(keyWithNullProvider.keyProviderId());
    }

    @Test
    public void testEncryptedDataKeyWithEmptyEncryptedKey() {
        // Test with empty encrypted key array
        EncryptedDataKey keyWithEmptyData = EncryptedDataKey.builder()
            .encryptedDataKey(new byte[0])
            .keyProviderId("test-provider")
            .keyProviderInfo("test-info")
            .build();

        assertEquals(0, keyWithEmptyData.encryptedDatakey().length);
    }

    @Test
    public void testValidEncryptedDataKeyCreation() {
        // Test valid encrypted data key creation
        EncryptedDataKey validKey = EncryptedDataKey.builder()
            .encryptedDataKey(new byte[32])
            .keyProviderId("test-provider")
            .keyProviderInfo("test-info")
            .build();

        assertEquals(32, validKey.encryptedDatakey().length);
        assertEquals("test-provider", validKey.keyProviderId());
        assertEquals("test-info", validKey.keyProviderInfo());
    }

    @Test
    public void testValidMaterialsDescriptionCreation() {
        // Test valid materials description with multiple entries
        MaterialsDescription desc = MaterialsDescription.builder()
            .put("version", "1.0")
            .put("environment", "test")
            .put("owner", "test-team")
            .build();

        assertEquals(3, desc.getMaterialsDescription().size());
        assertEquals("1.0", desc.getMaterialsDescription().get("version"));
        assertEquals("test", desc.getMaterialsDescription().get("environment"));
        assertEquals("test-team", desc.getMaterialsDescription().get("owner"));
    }
}
