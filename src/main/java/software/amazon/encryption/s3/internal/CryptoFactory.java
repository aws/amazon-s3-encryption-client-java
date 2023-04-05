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
package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

public class CryptoFactory {
    public static Cipher createCipher(String algorithm, Provider provider)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        // if the user has specified a provider, go with that.
        if (provider != null) {
            return Cipher.getInstance(algorithm, provider);
        }

        // Otherwise, go with the default provider.
        return Cipher.getInstance(algorithm);
    }

    public  static KeyGenerator generateKey(String algorithm, Provider provider) {
        KeyGenerator generator;
        try {
            if (provider == null) {
                generator = KeyGenerator.getInstance(algorithm);
            } else {
                generator = KeyGenerator.getInstance(algorithm, provider);
            }
        }  catch (NoSuchAlgorithmException e) {
            throw new S3EncryptionClientException("Unable to generate a(n) " + algorithm + " data key", e);
        }
        return generator;
    }
}
