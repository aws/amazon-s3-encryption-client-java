// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.S3EncryptionClientSecurityException;
import software.amazon.encryption.s3.materials.CryptographicMaterials;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;

/**
 * Composes a CMM to provide S3 specific functionality
 */
public class CipherProvider {

    private final CryptographicMaterialsManager cmm;

    public CipherProvider(final CryptographicMaterialsManager cmm) {
        this.cmm = cmm;
    }

    /**
     * Given some materials and an IV, create and init a Cipher object.
     * @param materials the materials which dictate e.g. algorithm suite
     * @param iv the IV, it MUST be initialized before use
     * @return a Cipher object, initialized and ready to use
     */
    public static Cipher createAndInitCipher(final CryptographicMaterials materials, byte[] iv) {
        // Validate that the IV has been populated. There is a small chance
        // that an IV containing only 0s is (validly) randomly generated,
        // but the tradeoff is worth the protection, and an IV of 0s is
        // not entirely unlike randomly generating "password" as your password.
        if (Arrays.equals(iv, new byte[iv.length])) {
            throw new S3EncryptionClientSecurityException("IV has not been initialized!");
        }
        try {
            Cipher cipher = CryptoFactory.createCipher(materials.algorithmSuite().cipherName(), materials.cryptoProvider());
            switch (materials.algorithmSuite()) {
                case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
                    cipher.init(materials.cipherMode().opMode(), materials.dataKey(), new GCMParameterSpec(materials.algorithmSuite().cipherTagLengthBits(), iv));
                    break;
                case ALG_AES_256_CTR_IV16_TAG16_NO_KDF:
                case ALG_AES_256_CBC_IV16_NO_KDF:
                    if (materials.cipherMode().opMode() == Cipher.ENCRYPT_MODE) {
                        throw new S3EncryptionClientException("Encryption is not supported for algorithm: " + materials.algorithmSuite().cipherName());
                    }
                    cipher.init(materials.cipherMode().opMode(), materials.dataKey(), new IvParameterSpec(iv));
                    break;
                default:
                    throw new S3EncryptionClientException("Unknown algorithm: " + materials.algorithmSuite().cipherName());
            }
            return cipher;
        } catch (Exception exception) {
            throw new S3EncryptionClientException(exception.getMessage(), exception);
        }
    }

}
