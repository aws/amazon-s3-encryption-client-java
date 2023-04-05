// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import software.amazon.awssdk.services.s3.model.S3Request;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.CipherMode;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Provider;
import java.util.Map;

public interface CryptographicMaterials {
    AlgorithmSuite algorithmSuite();

    S3Request s3Request();

    Map<String, String> encryptionContext();

    SecretKey dataKey();

    Provider cryptoProvider();

    CipherMode cipherMode();

    Cipher getCipher(byte[] iv);

}
