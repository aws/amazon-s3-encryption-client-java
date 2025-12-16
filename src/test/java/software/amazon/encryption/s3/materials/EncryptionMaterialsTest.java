// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.CipherMode;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EncryptionMaterialsTest {

    private List<EncryptedDataKey> encryptedDataKeys = new ArrayList();
    private byte[] plaintextDataKey;
    private PutObjectRequest s3Request;
    private EncryptionMaterials actualEncryptionMaterials;
    private Map<String, String> encryptionContext = new HashMap<>();


    @BeforeEach
    public void setUp() {
        s3Request = PutObjectRequest.builder().bucket("testBucket").key("testKey").build();
        encryptionContext.put("Key","Value");
        encryptedDataKeys.add(EncryptedDataKey.builder().keyProviderId("testKeyProviderId").build());
        plaintextDataKey = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
        actualEncryptionMaterials = EncryptionMaterials.builder()
                .s3Request(s3Request)
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .encryptionContext(encryptionContext)
                .encryptedDataKeys(encryptedDataKeys)
                .plaintextDataKey(plaintextDataKey)
                .build();
    }
    @Test
    void testS3Request() {
        assertEquals(s3Request, actualEncryptionMaterials.s3Request());
    }

    @Test
    void testAlgorithmSuite() {
        assertEquals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, actualEncryptionMaterials.algorithmSuite());
        assertNotEquals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF, actualEncryptionMaterials.algorithmSuite());
    }

    @Test
    void testEncryptionContext() {
        assertEquals(encryptionContext, actualEncryptionMaterials.encryptionContext());
    }

    @Test
    void testEncryptedDataKeys() {
        assertEquals(encryptedDataKeys, actualEncryptionMaterials.encryptedDataKeys());
    }

    @Test
    void testPlaintextDataKey() {
        assertEquals(Arrays.toString(plaintextDataKey), Arrays.toString(actualEncryptionMaterials.plaintextDataKey()));
    }

    @Test
    void testCipherMode() {
        assertEquals(CipherMode.ENCRYPT, actualEncryptionMaterials.cipherMode());
    }

    @Test
    void testSetIvAndMessageId() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        byte[] messageId = new byte[28];
        secureRandom.nextBytes(messageId);

        assertNull(actualEncryptionMaterials.iv());
        assertNull(actualEncryptionMaterials.messageId());

        actualEncryptionMaterials.setIvAndMessageId(iv, messageId);
        assertTrue(MessageDigest.isEqual(iv, actualEncryptionMaterials.iv()));
        assertTrue(MessageDigest.isEqual(messageId, actualEncryptionMaterials.messageId()));
    }

    @Test
    void testToBuilder() {
        EncryptionMaterials actualToBuilder = actualEncryptionMaterials.toBuilder().build();
        assertEquals(s3Request, actualToBuilder.s3Request());
        assertEquals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, actualToBuilder.algorithmSuite());
        assertEquals(encryptionContext, actualToBuilder.encryptionContext());
        assertEquals(encryptedDataKeys, actualToBuilder.encryptedDataKeys());
        assertEquals(Arrays.toString(plaintextDataKey), Arrays.toString(actualToBuilder.plaintextDataKey()));
    }
}