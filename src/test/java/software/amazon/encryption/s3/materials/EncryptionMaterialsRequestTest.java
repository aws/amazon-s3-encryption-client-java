/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
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