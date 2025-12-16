// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class EncryptedDataKeyTest {

    private EncryptedDataKey actualEncryptedDataKey;
    private byte[] encryptedDataKey;
    private String keyProviderId;
    private String keyProviderInfo;
    
    @BeforeEach
    public void setUp() {
        keyProviderId = "testKeyProviderId";
        keyProviderInfo = "test";
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
        assertEquals(keyProviderInfo, actualEncryptedDataKey.keyProviderInfo());
    }

    @Test
    public void ciphertext() {
        assertEquals(Arrays.toString(encryptedDataKey), Arrays.toString(actualEncryptedDataKey.encryptedDatakey()));
    }
}