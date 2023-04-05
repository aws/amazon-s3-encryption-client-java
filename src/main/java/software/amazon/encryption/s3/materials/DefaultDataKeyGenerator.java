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
