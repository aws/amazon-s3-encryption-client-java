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

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class EncryptedDataKeyTest {

    private EncryptedDataKey actualEncryptedDataKey;
    private byte[] encryptedDataKey;
    private String keyProviderId;
    private byte[] keyProviderInfo;
    
    @BeforeEach
    public void setUp() {
        keyProviderId = "testKeyProviderId";
        keyProviderInfo = new byte[]{20, 10, 30, 5};
        encryptedDataKey = new byte[]{20, 10, 30, 5};

        actualEncryptedDataKey = EncryptedDataKey.builder()
                .keyProviderId(keyProviderId)
                .keyProviderInfo(keyProviderInfo)
                .encryptedDataKey(encryptedDataKey)
                .build();
    }

    @Test
    public void keyProviderId() {
        assertEquals(keyProviderId, actualEncryptedDataKey.keyProviderId());
    }

    @Test
    public void keyProviderInfo() {
        assertEquals(Arrays.toString(keyProviderInfo), Arrays.toString(actualEncryptedDataKey.keyProviderInfo()));
    }

    @Test
    public void ciphertext() {
        assertEquals(Arrays.toString(encryptedDataKey), Arrays.toString(actualEncryptedDataKey.encryptedDatakey()));
    }
}