// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.CryptoFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Provider;

public class DefaultDataKeyGenerator implements DataKeyGenerator {

    public SecretKey generateDataKey(AlgorithmSuite algorithmSuite, Provider provider) {
        KeyGenerator generator = CryptoFactory.generateKey(algorithmSuite.dataKeyAlgorithm(), provider);
        generator.init(algorithmSuite.dataKeyLengthBits());
        return generator.generateKey();
    }
}
