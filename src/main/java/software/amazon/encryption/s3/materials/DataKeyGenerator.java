// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import javax.crypto.SecretKey;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.security.Provider;

@FunctionalInterface
public interface DataKeyGenerator {
    SecretKey generateDataKey(AlgorithmSuite algorithmSuite, Provider provider);
}
