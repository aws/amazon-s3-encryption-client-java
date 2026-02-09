// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
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
