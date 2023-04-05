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