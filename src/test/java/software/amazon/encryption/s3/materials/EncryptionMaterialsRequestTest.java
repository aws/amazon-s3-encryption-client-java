// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class EncryptionMaterialsRequestTest {

    private PutObjectRequest request;
    private EncryptionMaterialsRequest actualRequestBuilder;
    private Map<String, String> encryptionContext = new HashMap<>();

    @BeforeEach
    public void setUp() {
        request = PutObjectRequest.builder().bucket("testBucket").key("testKey").build();
        encryptionContext.put("Key","Value");

        actualRequestBuilder = EncryptionMaterialsRequest.builder()
                .s3Request(request).encryptionContext(encryptionContext).build();
    }

    @Test
    public void testS3Request() {
        assertEquals(request, actualRequestBuilder.s3Request());
    }

    @Test
    public void testEncryptionContext() {
        assertEquals(encryptionContext, actualRequestBuilder.encryptionContext());
    }
}