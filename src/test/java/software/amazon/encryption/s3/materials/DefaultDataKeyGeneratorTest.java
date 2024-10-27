// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DefaultDataKeyGeneratorTest {

    private final DataKeyGenerator dataKeyGenerator = new DefaultDataKeyGenerator();

    @Test
    public void testGenerateDataKey() {
        SecretKey actualSecretKey = dataKeyGenerator.generateDataKey(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, null);
        assertEquals("AES", actualSecretKey.getAlgorithm());
        actualSecretKey = dataKeyGenerator.generateDataKey(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, new BouncyCastleProvider());
        assertEquals("AES", actualSecretKey.getAlgorithm());
    }
}