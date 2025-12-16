// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import software.amazon.encryption.s3.S3EncryptionClientException;

public class KeyringValidationTest {

    private static SecretKey AES_KEY;
    private static KeyPair RSA_KEY_PAIR;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        RSA_KEY_PAIR = keyPairGen.generateKeyPair();
    }

    @Test
    public void testAesKeyringWithInvalidKeySize() throws NoSuchAlgorithmException {
        // Test with 128-bit key (should work)
        KeyGenerator keyGen128 = KeyGenerator.getInstance("AES");
        keyGen128.init(128);
        SecretKey aes128Key = keyGen128.generateKey();
        
        assertDoesNotThrow(() ->
            AesKeyring.builder().wrappingKey(aes128Key).build()
        );

        // Test with invalid key algorithm
        KeyGenerator desKeyGen = KeyGenerator.getInstance("DES");
        desKeyGen.init(56);
        SecretKey desKey = desKeyGen.generateKey();
        
        assertThrows(S3EncryptionClientException.class, () ->
            AesKeyring.builder().wrappingKey(desKey).build()
        );
    }

    @Test
    public void testPartialRsaKeyPairValidation() {
        // Test with null private and public key
        assertThrows(S3EncryptionClientException.class, () ->
            new PartialRsaKeyPair(null, null)
        );

        // Test with only private key (should work for decryption)
        assertDoesNotThrow(() ->
            new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), null)
        );

        // Test with only public key (should work for encryption)
        assertDoesNotThrow(() ->
            new PartialRsaKeyPair(null, RSA_KEY_PAIR.getPublic())
        );
    }

    @Test
    public void testKmsKeyringWithInvalidKeyId() {
        // Test with empty key ID
        assertThrows(S3EncryptionClientException.class, () ->
            KmsKeyring.builder().wrappingKeyId("").build()
        );

        // Test with null key ID
        assertThrows(S3EncryptionClientException.class, () ->
            KmsKeyring.builder().wrappingKeyId(null).build()
        );
    }

    @Test
    public void testMaterialsDescriptionEdgeCases() {
        // Test with very long key/value pairs
        StringBuilder longKeyBuilder = new StringBuilder();
        StringBuilder longValueBuilder = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            longKeyBuilder.append("a");
            longValueBuilder.append("b");
        }
        String longKey = longKeyBuilder.toString();
        String longValue = longValueBuilder.toString();
        
        assertDoesNotThrow(() ->
            MaterialsDescription.builder().put(longKey, longValue).build()
        );

        // Test with special characters
        assertDoesNotThrow(() ->
            MaterialsDescription.builder()
                .put("key-with-special-chars!@#$%", "value-with-unicode-测试")
                .build()
        );
    }

    @Test
    public void testAesKeyringWithNullWrappingKey() {
        assertThrows(S3EncryptionClientException.class, () ->
            AesKeyring.builder().wrappingKey(null).build()
        );
    }

    @Test
    public void testAesKeyringWithNullSecureRandom() {
        assertThrows(S3EncryptionClientException.class, () ->
            AesKeyring.builder()
                .wrappingKey(AES_KEY)
                .secureRandom(null)
                .build()
        );
    }

    @Test
    public void testAesKeyringWithNullDataKeyGenerator() {
        assertThrows(S3EncryptionClientException.class, () ->
            AesKeyring.builder()
                .wrappingKey(AES_KEY)
                .dataKeyGenerator(null)
                .build()
        );
    }

    @Test
    public void testRsaKeyringWithNullKeyPair() {
        assertThrows(S3EncryptionClientException.class, () ->
            RsaKeyring.builder().wrappingKeyPair(null).build()
        );
    }

    @Test
    public void testValidKeyringCreation() {
        // Test valid AES keyring creation
        assertDoesNotThrow(() -> {
            AesKeyring aesKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY)
                .build();
            aesKeyring.toString(); // Just to use the variable
        });

        // Test valid RSA keyring creation
        assertDoesNotThrow(() -> {
            RsaKeyring rsaKeyring = RsaKeyring.builder()
                .wrappingKeyPair(new PartialRsaKeyPair(RSA_KEY_PAIR))
                .build();
            rsaKeyring.toString(); // Just to use the variable
        });
    }
}
