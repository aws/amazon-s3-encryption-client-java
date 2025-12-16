// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.S3EncryptionClientSecurityException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.CryptographicMaterials;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

public class CipherProviderTest {

    private SecureRandom secureRandom;
    private Provider mockProvider;
    private static final byte[] EMPTY_KEY_COMMITMENT = new byte[28];
    private static final byte[] EMPTY_MESSAGE_ID = new byte[28];
    private static final byte[] EMPTY_IV = new byte[12];
    private static final byte[] FIXED_IV_FOR_COMMIT_ALG = new byte[]{
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
    };

    @BeforeEach
    public void setUp() {
        secureRandom = new SecureRandom();
        mockProvider = null; // Use default provider
    }

    // Helper method to create a test data key
    private SecretKey createTestDataKey(int lengthBytes) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(lengthBytes * 8);
        return keyGen.generateKey();
    }

    // Helper method to create encryption materials using builder
    private EncryptionMaterials createEncryptionMaterials(AlgorithmSuite algorithmSuite, SecretKey dataKey) {
        return EncryptionMaterials.builder()
                .algorithmSuite(algorithmSuite)
                .plaintextDataKey(dataKey.getEncoded())
                .cryptoProvider(mockProvider)
                .plaintextLength(1024)
                .build();
    }

    // Helper method to create decryption materials using builder
    private DecryptionMaterials createDecryptionMaterials(AlgorithmSuite algorithmSuite, SecretKey dataKey, byte[] keyCommitment) {
        return DecryptionMaterials.builder()
                .algorithmSuite(algorithmSuite)
                .plaintextDataKey(dataKey.getEncoded())
                .cryptoProvider(mockProvider)
                .keyCommitment(keyCommitment)
                .ciphertextLength(1024)
                .build();
    }

    @Test
    public void testCreateAndInitCipherWithCommittingAlgorithmZeroMessageId() throws Exception {
        //= specification/s3-encryption/encryption.md#cipher-initialization
        //= type=test
        //# The client SHOULD validate that the generated IV or Message ID is not zeros.
        SecretKey dataKey = createTestDataKey(32);
        EncryptionMaterials materials = createEncryptionMaterials(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, dataKey);

        byte[] messageId = new byte[materials.algorithmSuite().commitmentNonceLengthBytes()]; // All zeros
        byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];

        S3EncryptionClientSecurityException exception = assertThrows(S3EncryptionClientSecurityException.class,
                () -> CipherProvider.createAndInitCipher(materials, iv, messageId));

        assertEquals("MessageId has not been initialized!", exception.getMessage());
    }

    @Test
    public void testCreateAndInitCipherWithNonCommittingAlgorithmValidIV() throws Exception {
        //= specification/s3-encryption/encryption.md#cipher-initialization
        //= type=test
        //# The client SHOULD validate that the generated IV or Message ID is not zeros.
        SecretKey dataKey = createTestDataKey(32);
        CryptographicMaterials materials = createEncryptionMaterials(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, dataKey);

        byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()]; // 96 bits / 8 = 12 bytes
        secureRandom.nextBytes(iv);
        byte[] messageId = null;

        Cipher cipher = CipherProvider.createAndInitCipher(materials, iv, messageId);

        assertNotNull(cipher);
        assertEquals("AES/GCM/NoPadding", cipher.getAlgorithm());
    }

    @Test
    public void testCreateAndInitCipherWithNonCommittingAlgorithmZeroIV() throws Exception {
        //= specification/s3-encryption/encryption.md#cipher-initialization
        //= type=test
        //# The client SHOULD validate that the generated IV or Message ID is not zeros.
        SecretKey dataKey = createTestDataKey(32);
        CryptographicMaterials materials = createEncryptionMaterials(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, dataKey);

        byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()]; // All zeros
        byte[] messageId = null;

        S3EncryptionClientSecurityException exception = assertThrows(S3EncryptionClientSecurityException.class, () -> CipherProvider.createAndInitCipher(materials, iv, messageId));

        assertEquals("IV has not been initialized!", exception.getMessage());
    }


    @Test
    public void testCreateAndInitCipherALG_AES_256_GCM_IV12_TAG16_NO_KDF() throws Exception {
        SecretKey dataKey = createTestDataKey(32);
        CryptographicMaterials materials = createEncryptionMaterials(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, dataKey);

        byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];
        byte[] messageId = null;
        if (materials.algorithmSuite().isCommitting()) {
            messageId = new byte[materials.algorithmSuite().commitmentNonceLengthBytes()];
            secureRandom.nextBytes(messageId);
            Arrays.fill(iv, (byte) 0x01);
        } else {
            secureRandom.nextBytes(iv);
        }

        //= specification/s3-encryption/encryption.md#alg-aes-256-gcm-iv12-tag16-no-kdf
        //= type=test
        //# The client MUST initialize the cipher, or call an AES-GCM encryption API, with the plaintext data key, the generated IV,
        //# and the tag length defined in the Algorithm Suite when encrypting with ALG_AES_256_GCM_IV12_TAG16_NO_KDF.
        Cipher cipher = CipherProvider.createAndInitCipher(materials, iv, messageId);

        assertNotNull(cipher);
        assertEquals("AES/GCM/NoPadding", cipher.getAlgorithm());

        // Verify cipher was initialized with correct parameters
        GCMParameterSpec params = cipher.getParameters().getParameterSpec(GCMParameterSpec.class);
        assertEquals(128, params.getTLen()); // 128-bit tag length
        assertArrayEquals(iv, params.getIV());
    }

    @Test
    public void testCreateAndInitCipherALG_AES_256_CTR_IV16_TAG16_NO_KDF_EncryptionFails() throws Exception {
        //= specification/s3-encryption/encryption.md#alg-aes-256-ctr-iv16-tag16-no-kdf
        //= type=test
        //# Attempts to encrypt using AES-CTR MUST fail.
        SecretKey dataKey = createTestDataKey(32);
        CryptographicMaterials materials = createEncryptionMaterials(AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF, dataKey);

        byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];
        secureRandom.nextBytes(iv);
        byte[] messageId = new byte[16];

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> CipherProvider.createAndInitCipher(materials, iv, messageId));

        assertTrue(exception.getMessage().contains("Encryption is not supported for algorithm"));
    }

    @Test
    public void testCreateAndInitCipherALG_AES_256_CTR_IV16_TAG16_NO_KDF_DecryptionSucceeds() throws Exception {
        SecretKey dataKey = createTestDataKey(32);
        CryptographicMaterials materials = createDecryptionMaterials(AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF, dataKey, EMPTY_KEY_COMMITMENT);

        byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];
        secureRandom.nextBytes(iv);
        byte[] messageId = null;

        Cipher cipher = CipherProvider.createAndInitCipher(materials, iv, messageId);

        assertNotNull(cipher);
        assertEquals("AES/CTR/NoPadding", cipher.getAlgorithm());
    }

    @Test
    public void testCreateAndInitCipherALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY_EncryptionFails() throws Exception {
        //= specification/s3-encryption/encryption.md#alg-aes-256-ctr-hkdf-sha512-commit-key
        //= type=test
        //# Attempts to encrypt using key committing AES-CTR MUST fail.
        SecretKey dataKey = createTestDataKey(32);
        CryptographicMaterials materials = createEncryptionMaterials(AlgorithmSuite.ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY, dataKey);

        byte[] messageId = new byte[materials.algorithmSuite().commitmentNonceLengthBytes()];
        secureRandom.nextBytes(messageId);
        byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> CipherProvider.createAndInitCipher(materials, iv, messageId));

        assertTrue(exception.getMessage().contains("Encryption is not supported for algorithm"));
    }

    @Test
    public void testCreateAndInitCipherALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY_DecryptionSucceeds() throws Exception {
        //= specification/s3-encryption/encryption.md#alg-aes-256-gcm-hkdf-sha512-commit-key
        //= type=test
        //# The client MUST use HKDF to derive the key commitment value and the derived encrypting key
        //# as described in [Key Derivation](key-derivation.md).
        SecretKey dataKey = createTestDataKey(32);
        byte[] keyCommitment = new byte[28];
        secureRandom.nextBytes(keyCommitment);
        DecryptionMaterials materials = createDecryptionMaterials(AlgorithmSuite.ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY, dataKey, keyCommitment);

        byte[] messageId = new byte[materials.algorithmSuite().commitmentNonceLengthBytes()];
        secureRandom.nextBytes(messageId);
        byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];
        secureRandom.nextBytes(iv);

        // This test will fail due to key commitment mismatch, but that's expected behavior
        // The important part is that it attempts to derive the key and validate commitment
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> CipherProvider.createAndInitCipher(materials, iv, messageId));
        assertEquals(S3EncryptionClientSecurityException.class, exception.getCause().getClass());

        assertTrue(exception.getMessage().contains("Key commitment validation failed. The derived key commitment does not match the stored key commitment value. This indicates potential data tampering or corruption."));
    }

    @Test
    public void testCreateAndInitCipherALG_AES_256_CBC_IV16_NO_KDF_EncryptionFails() throws Exception {
        SecretKey dataKey = createTestDataKey(32);
        CryptographicMaterials materials = createEncryptionMaterials(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF, dataKey);

        byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];
        secureRandom.nextBytes(iv);
        byte[] messageId = null;

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> CipherProvider.createAndInitCipher(materials, iv, messageId));

        assertTrue(exception.getMessage().contains("Encryption is not supported for algorithm"));
    }

    @Test
    public void testCreateAndInitCipherALG_AES_256_CBC_IV16_NO_KDF_DecryptionSucceeds() throws Exception {
        SecretKey dataKey = createTestDataKey(32);
        CryptographicMaterials materials = createDecryptionMaterials(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF, dataKey, EMPTY_KEY_COMMITMENT);

        byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];
        secureRandom.nextBytes(iv);
        byte[] messageId = null;

        Cipher cipher = CipherProvider.createAndInitCipher(materials, iv, messageId);

        assertNotNull(cipher);
        assertEquals("AES/CBC/PKCS5Padding", cipher.getAlgorithm());
    }

    @Test
    public void testKeyDerivationInputKeyMaterialLengthValidation() throws Exception {
        //= specification/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //# - The length of the input keying material MUST equal the key derivation input length specified by the
        //# algorithm suite commit key derivation setting.
        SecretKey wrongSizeDataKey = createTestDataKey(16); // Wrong size - should be 32 bytes
        DecryptionMaterials materials = createDecryptionMaterials(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, wrongSizeDataKey, EMPTY_KEY_COMMITMENT);

        byte[] messageId = new byte[materials.algorithmSuite().commitmentNonceLengthBytes()];
        secureRandom.nextBytes(messageId);
        byte[] iv = FIXED_IV_FOR_COMMIT_ALG.clone();

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> CipherProvider.createAndInitCipher(materials, iv, messageId));

        assertEquals("Length of Input key material does not match the expected value!", exception.getMessage());
    }

    @Test
    public void testKeyDerivationMessageIdLengthValidation() throws Exception {
        //= specification/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //# - The salt MUST be the Message ID with the length defined in the algorithm suite.
        SecretKey dataKey = createTestDataKey(32);
        DecryptionMaterials materials = createDecryptionMaterials(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, dataKey, EMPTY_KEY_COMMITMENT);

        byte[] wrongSizeMessageId = new byte[16]; // Wrong size - should be 28 bytes
        secureRandom.nextBytes(wrongSizeMessageId);
        byte[] iv = FIXED_IV_FOR_COMMIT_ALG.clone();

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> CipherProvider.createAndInitCipher(materials, iv, wrongSizeMessageId));

        assertEquals("Length of Input Message ID does not match the expected value!", exception.getMessage());
    }

    @Test
    public void testKeyCommitmentValidationBothSuccessAndFailurePaths() throws Exception {
        //= specification/s3-encryption/decryption.md#decrypting-with-commitment
        //= type=test
        //# When using an algorithm suite which supports key commitment, the client MUST verify that the
        //# [derived key commitment](./key-derivation.md#hkdf-operation) contains the same bytes as the stored key
        //# commitment retrieved from the stored object's metadata.
        //= specification/s3-encryption/decryption.md#decrypting-with-commitment
        //= type=test
        //# When using an algorithm suite which supports key commitment, the client MUST verify the key commitment values match
        //# before deriving the [derived encryption key](./key-derivation.md#hkdf-operation).

        // Step 1: Generate a secret key
        SecretKey dataKey = createTestDataKey(32);

        byte[] messageId = new byte[AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.commitmentNonceLengthBytes()];
        secureRandom.nextBytes(messageId);

        // Step 2: Manually derive the commitment key by mimicking the generateDerivedEncryptionKey logic
        //= specification/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //# - The hash function MUST be specified by the algorithm suite commitment settings.
        String macAlgorithm = AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.kdfHashAlgorithm();
        HmacKeyDerivationFunction kdf = HmacKeyDerivationFunction.getInstance(macAlgorithm, mockProvider);
        kdf.init(dataKey.getEncoded(), messageId);

        // Create the commitment key label exactly as CipherProvider does
        //= specification/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //# - The input info MUST be a concatenation of the algorithm suite ID as bytes followed by the string COMMITKEY as UTF8 encoded bytes.
        byte[] commitKeyLabel = "__COMMITKEY".getBytes("UTF-8");
        final short algId = (short) AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.id();
        commitKeyLabel[0] = (byte) ((algId >> 8) & 0xFF);
        commitKeyLabel[1] = (byte) (algId & 0xFF);

        // Derive the correct key commitment
        //= specification/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //# - The length of the output keying material MUST equal the commit key length specified by the supported algorithm suites.
        byte[] correctKeyCommitment = kdf.deriveKey(commitKeyLabel, AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.commitmentLengthBytes());

        // Step 3: Create decryption materials with the same secret key and correct key commitment
        DecryptionMaterials correctMaterials = createDecryptionMaterials(
            AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
            dataKey,
            correctKeyCommitment
        );

        //= specification/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //# - The length of the output keying material MUST equal the encryption key length specified by the algorithm suite encryption settings.
        SecretKey key = CipherProvider.generateDerivedEncryptionKey(correctMaterials, messageId);
        assertEquals(correctMaterials.algorithmSuite().dataKeyLengthBytes(), key.getEncoded().length);

        byte[] iv = FIXED_IV_FOR_COMMIT_ALG.clone(); //  IV for committing algorithm

        // SUCCESS PATH: This should succeed because the key commitment matches what will be derived
        Cipher cipher = CipherProvider.createAndInitCipher(correctMaterials, iv, messageId);
        assertNotNull(cipher);
        assertEquals("AES/GCM/NoPadding", cipher.getAlgorithm());

        // Verify proper cipher initialization
        GCMParameterSpec params = cipher.getParameters().getParameterSpec(GCMParameterSpec.class);
        //= specification/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //# When encrypting or decrypting with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        //# the IV used in the AES-GCM content encryption/decryption MUST consist entirely of bytes with the value 0x01.
        assertArrayEquals(FIXED_IV_FOR_COMMIT_ALG.clone(), params.getIV()); // IV for committing algorithm
        assertEquals(128, params.getTLen()); // 128-bit tag length

        // Step 4: Create decryption materials with wrong key commitment to ensure failure
        byte[] wrongKeyCommitment = new byte[28];
        secureRandom.nextBytes(wrongKeyCommitment);
        DecryptionMaterials wrongMaterials = createDecryptionMaterials(
                AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
                dataKey,
                wrongKeyCommitment
        );

        // FAILURE PATH: This should fail because the key commitment doesn't match
        //= specification/s3-encryption/decryption.md#decrypting-with-commitment
        //= type=test
        //# When using an algorithm suite which supports key commitment, the client MUST throw an exception when the
        //# derived key commitment value and stored key commitment value do not match.
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class,
                () -> CipherProvider.createAndInitCipher(wrongMaterials, iv, messageId));

        assertEquals(S3EncryptionClientSecurityException.class, exception.getCause().getClass());
        String expectedMessage = "Key commitment validation failed. The derived key commitment does not match the stored key commitment value. This indicates potential data tampering or corruption.";
        assertEquals(expectedMessage, exception.getCause().getMessage());
    }
}
