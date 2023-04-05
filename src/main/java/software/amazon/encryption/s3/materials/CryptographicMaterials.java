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
