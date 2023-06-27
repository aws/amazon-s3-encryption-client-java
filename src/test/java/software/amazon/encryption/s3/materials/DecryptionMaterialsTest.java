// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class DecryptionMaterialsTest {

    private DecryptionMaterials actualDecryptionMaterials;
    private GetObjectRequest s3Request;
    private Map<String, String> encryptionContext = new HashMap<>();

    @BeforeEach
    public void setUp() {
        s3Request = GetObjectRequest.builder().bucket("testBucket").key("testKey").build();
        encryptionContext.put("testKey", "testValue");

        actualDecryptionMaterials = DecryptionMaterials.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .s3Request(s3Request)
                .encryptionContext(encryptionContext)
                .build();
    }

    @Test
    public  void testS3Request() {
        assertEquals(s3Request, actualDecryptionMaterials.s3Request());
    }

    @Test
    public void testAlgorithmSuite() {
        assertEquals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, actualDecryptionMaterials.algorithmSuite());
        assertNotEquals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF, actualDecryptionMaterials.algorithmSuite());
    }

    @Test
    public void testEncryptionContext() {
        assertEquals(encryptionContext, actualDecryptionMaterials.encryptionContext());
    }
}

