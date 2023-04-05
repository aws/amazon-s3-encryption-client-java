// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptedDataKey;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.Mockito.mock;

public class ContentMetadataTest {

    private EncryptedDataKey encryptedDataKey;
    private ContentMetadata actualContentMetadata;
    private String encryptedDataKeyAlgorithm;
    private final Map<String, String> encryptedDataKeyContext = new HashMap<>();
    private byte[] contentIv;

    @BeforeEach
    public void setUp() {
        encryptedDataKey = mock(EncryptedDataKey.class);
        contentIv = "Test String".getBytes();
        encryptedDataKeyAlgorithm =   "Test Algorithm";
        encryptedDataKeyContext.put("testKey", "testValue");

        actualContentMetadata = ContentMetadata.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .encryptedDataKey(encryptedDataKey)
                .contentIv(contentIv)
                .encryptedDataKeyAlgorithm(encryptedDataKeyAlgorithm)
                .encryptedDataKeyContext(encryptedDataKeyContext)
                .build();
    }

    @Test
    public void testAlgorithmSuite() {
        assertEquals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, actualContentMetadata.algorithmSuite());
        assertNotEquals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF, actualContentMetadata.algorithmSuite());
    }

    @Test
    public void testEncryptedDataKey() {
        assertEquals(encryptedDataKey, actualContentMetadata.encryptedDataKey());
    }

    @Test
    public void testEncryptedDataKeyAlgorithm() {
        assertEquals(encryptedDataKeyAlgorithm, actualContentMetadata.encryptedDataKeyAlgorithm());
    }

    @Test
    public void testEncryptedDataKeyContext() {
        assertEquals(encryptedDataKeyContext, actualContentMetadata.encryptedDataKeyContext());
    }

    @Test
    public void testContentIv() {
        assertEquals(Arrays.toString(contentIv),Arrays.toString(actualContentMetadata.contentIv()));
    }
}

