// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.DefaultCryptoMaterialsManager;

public class S3EncryptionClientBuilderValidationTest {

    @Test
    public void testBuilderWithMultipleKeyringTypesFails() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();
        
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair rsaKeyPair = keyPairGen.generateKeyPair();

        // Test AES + RSA
        S3EncryptionClientException exception1 = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .aesKey(aesKey)
                .rsaKeyPair(rsaKeyPair)
                .build()
        );
        assertTrue(exception1.getMessage().contains("Only one may be set of"));

        // Test AES + KMS
        S3EncryptionClientException exception2 = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .aesKey(aesKey)
                .kmsKeyId("test-key-id")
                .build()
        );
        assertTrue(exception2.getMessage().contains("Only one may be set of"));

        // Test RSA + KMS
        S3EncryptionClientException exception3 = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .rsaKeyPair(rsaKeyPair)
                .kmsKeyId("test-key-id")
                .build()
        );
        assertTrue(exception3.getMessage().contains("Only one may be set of"));
    }

    @Test
    public void testBuilderWithNoKeyringFails() {
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build()
        );
        assertTrue(exception.getMessage().contains("Exactly one must be set of"));
    }

    @Test
    public void testBuilderWithCMMAndKeyringFails() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();
        
        AesKeyring keyring = AesKeyring.builder().wrappingKey(aesKey).build();
        DefaultCryptoMaterialsManager cmm = DefaultCryptoMaterialsManager.builder()
            .keyring(keyring)
            .build();

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .aesKey(aesKey)
                .cryptoMaterialsManager(cmm)
                .build()
        );
        assertTrue(exception.getMessage().contains("Only one may be set of"));
    }

    @Test
    public void testBuilderWithInvalidBufferSizes() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        // Test buffer size too small
        S3EncryptionClientException exception1 = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .aesKey(aesKey)
                .setBufferSize(15L)
                .build()
        );
        assertTrue(exception1.getMessage().contains("Invalid buffer size"));

        // Test buffer size too large
        S3EncryptionClientException exception2 = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .aesKey(aesKey)
                .setBufferSize(68719476705L)
                .build()
        );
        assertTrue(exception2.getMessage().contains("Invalid buffer size"));
    }

    @Test
    public void testBuilderWithBufferSizeAndDelayedAuthFails() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () ->
                //= specification/s3-encryption/client.md#set-buffer-size
                //= type=test
                //# If Delayed Authentication mode is enabled, and the buffer size has been set to a value other than its default, the S3EC MUST throw an exception.
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .aesKey(aesKey)
                .setBufferSize(1024)
                .enableDelayedAuthenticationMode(true)
                .build()
        );
        assertTrue(exception.getMessage().contains("Buffer size cannot be set when delayed authentication mode is enabled"));
    }

    @Test
    public void testBuilderWithNullSecureRandomFails() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .aesKey(aesKey)
                .secureRandom(null)
                .build()
        );
        assertTrue(exception.getMessage().contains("SecureRandom provided to S3EncryptionClient cannot be null"));
    }

    @Test
    public void testBuilderWithInvalidCommitmentPolicyAlgorithmCombination() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        // Test REQUIRE_ENCRYPT with non-committing algorithm
        S3EncryptionClientException exception1 = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                    .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                    .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .aesKey(aesKey)
                    .build()
        );
        assertTrue(exception1.getMessage().contains("This client can ONLY be built with these Settings: Commitment Policy: FORBID_ENCRYPT_ALLOW_DECRYPT; Encryption Algorithm: ALG_AES_256_GCM_IV12_TAG16_NO_KDF."));

        // Test FORBID_ENCRYPT with committing algorithm
        S3EncryptionClientException exception2 = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                    .aesKey(aesKey)
                    .build()
        );
        assertTrue(exception2.getMessage().contains("This client can ONLY be built with these Settings: Commitment Policy: FORBID_ENCRYPT_ALLOW_DECRYPT; Encryption Algorithm: ALG_AES_256_GCM_IV12_TAG16_NO_KDF."));
    }

    @Test
    public void testBuilderWithLegacyAlgorithmFails() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                    .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                    .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF)
                    .aesKey(aesKey)
                    .build()
        );
        assertTrue(exception.getMessage().contains("This client can ONLY be built with these Settings: Commitment Policy: FORBID_ENCRYPT_ALLOW_DECRYPT; Encryption Algorithm: ALG_AES_256_GCM_IV12_TAG16_NO_KDF."));
    }

    @Test
    public void testBuilderWithWrappedS3EncryptionClientFails() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        S3EncryptionClient wrappedEncryptionClient = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .aesKey(aesKey)
                .build();

        // Should not be able to wrap an S3EncryptionClient
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .aesKey(aesKey)
                .wrappedClient(wrappedEncryptionClient)
                .build()
        );
        assertTrue(exception.getMessage().contains("Cannot use S3EncryptionClient as wrapped client"));

        wrappedEncryptionClient.close();
    }

    @Test
    public void testBuilderWithWrappedS3AsyncEncryptionClientFails() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        S3AsyncEncryptionClient wrappedAsyncEncryptionClient = S3AsyncEncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .aesKey(aesKey)
                .build();

        // Should not be able to wrap an S3AsyncEncryptionClient
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .aesKey(aesKey)
                .wrappedAsyncClient(wrappedAsyncEncryptionClient)
                .build()
        );
        assertTrue(exception.getMessage().contains("Cannot use S3AsyncEncryptionClient as wrapped client"));

        wrappedAsyncEncryptionClient.close();
    }

    @Test
    public void testBuilderWithInvalidAesKey() throws NoSuchAlgorithmException {
        // Test with DES key instead of AES
        KeyGenerator desKeyGen = KeyGenerator.getInstance("DES");
        desKeyGen.init(56);
        SecretKey desKey = desKeyGen.generateKey();

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .aesKey(desKey)
                .build()
        );
        assertTrue(exception.getMessage().contains("Invalid algorithm"));
        assertTrue(exception.getMessage().contains("expecting AES"));
    }

    @Test
    public void testBuilderWithInvalidRsaKey() throws NoSuchAlgorithmException {
        // Test with EC key instead of RSA
        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
        ecKeyGen.initialize(256);
        KeyPair ecKey = ecKeyGen.generateKeyPair();

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .rsaKeyPair(ecKey)
                .build()
        );
        assertTrue(exception.getMessage().contains("not a supported algorithm"));
        assertTrue(exception.getMessage().contains("Only RSA keys are supported"));
    }

    @Test
    public void testBuilderWithEmptyKmsKeyId() {
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .kmsKeyId("")
                .build()
        );
        assertTrue(exception.getMessage().contains("Kms Key ID cannot be empty or null"));
    }

    @Test
    public void testBuilderWithNullKmsKeyId() {
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () ->
            S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .kmsKeyId(null)
                .build()
        );
        assertTrue(exception.getMessage().contains("Only one may be set of"));
    }
}
