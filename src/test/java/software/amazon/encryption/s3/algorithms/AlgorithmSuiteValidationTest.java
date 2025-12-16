// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.algorithms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class AlgorithmSuiteValidationTest {

    @ParameterizedTest
    @EnumSource(AlgorithmSuite.class)
    public void testAlgorithmSuiteProperties(AlgorithmSuite suite) {
        // Test that all properties are consistent
        assertTrue(suite.dataKeyLengthBits() > 0);
        assertTrue(suite.dataKeyLengthBytes() == suite.dataKeyLengthBits() / 8);
        assertTrue(suite.iVLengthBytes() >= 0);
        // Cipher Length is -1 for AES/CTR AlgSuites
        // assertTrue(suite.cipherMaxContentLengthBytes() > 0);
        assertNotNull(suite.cipherName());
        assertNotNull(suite.dataKeyAlgorithm());
    }

    @Test
    public void testLegacyAlgorithmIdentification() {
        assertTrue(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF.isLegacy());
        assertTrue(AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF.isLegacy());
        assertFalse(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.isLegacy());
        assertFalse(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.isLegacy());
    }

    @Test
    public void testCommittingAlgorithmIdentification() {
        assertTrue(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.isCommitting());
        assertTrue(AlgorithmSuite.ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY.isCommitting());
        assertFalse(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.isCommitting());
        assertFalse(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF.isCommitting());
    }

    @Test
    public void testAlgorithmSuiteIdConversions() {
        for (AlgorithmSuite suite : AlgorithmSuite.values()) {
            assertEquals(String.valueOf(suite.id()), suite.idAsString());
            byte[] idBytes = suite.idAsBytes();
            assertEquals(2, idBytes.length);
            int reconstructedId = ((idBytes[0] & 0xFF) << 8) | (idBytes[1] & 0xFF);
            assertEquals(suite.id(), reconstructedId);
        }
    }

    @Test
    public void testContentLengthLimits() {
        // Test that GCM algorithms have appropriate limits
        assertTrue(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherMaxContentLengthBytes() > 0);
        assertTrue(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.cipherMaxContentLengthBytes() > 0);
        
        // Test that CBC has different limits than GCM
        assertNotEquals(
            AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF.cipherMaxContentLengthBytes(),
            AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherMaxContentLengthBytes()
        );
    }

    @Test
    public void testAlgorithmSuiteSpecificProperties() {
        // Test AES-256-GCM-IV12-TAG16-NO-KDF properties
        AlgorithmSuite gcmNoKdf = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
        assertEquals(256, gcmNoKdf.dataKeyLengthBits());
        assertEquals(32, gcmNoKdf.dataKeyLengthBytes());
        assertEquals(12, gcmNoKdf.iVLengthBytes());
        assertEquals(16, gcmNoKdf.cipherTagLengthBytes());
        assertEquals("AES/GCM/NoPadding", gcmNoKdf.cipherName());
        assertFalse(gcmNoKdf.isCommitting());
        assertEquals(0, gcmNoKdf.commitmentLengthBytes());

        // Test AES-256-GCM-HKDF-SHA512-COMMIT-KEY properties
        AlgorithmSuite gcmCommit = AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
        assertEquals(256, gcmCommit.dataKeyLengthBits());
        assertEquals(32, gcmCommit.dataKeyLengthBytes());
        assertEquals(12, gcmCommit.iVLengthBytes()); // 96 bits / 8
        assertEquals(16, gcmCommit.cipherTagLengthBytes());
        assertEquals("AES/GCM/NoPadding", gcmCommit.cipherName());
        assertTrue(gcmCommit.isCommitting());
        assertEquals(28, gcmCommit.commitmentLengthBytes()); // 224 bits / 8
        assertEquals("HmacSHA512", gcmCommit.kdfHashAlgorithm());

        // Test CBC properties
        AlgorithmSuite cbc = AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF;
        assertEquals(256, cbc.dataKeyLengthBits());
        assertEquals(16, cbc.iVLengthBytes());
        assertEquals(0, cbc.cipherTagLengthBytes()); // CBC has no tag
        assertEquals("AES/CBC/PKCS5Padding", cbc.cipherName());
        assertTrue(cbc.isLegacy());
        assertFalse(cbc.isCommitting());
    }

    @Test
    public void testAlgorithmSuiteUniqueIds() {
        AlgorithmSuite[] suites = AlgorithmSuite.values();
        for (int i = 0; i < suites.length; i++) {
            for (int j = i + 1; j < suites.length; j++) {
                assertNotEquals(suites[i].id(), suites[j].id(), 
                    "Algorithm suites should have unique IDs: " + suites[i] + " vs " + suites[j]);
            }
        }
    }
}
