// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_REGION;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoConfigurationV2;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import com.amazonaws.services.s3.model.EncryptedPutObjectRequest;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.KMSEncryptionMaterials;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.SimpleMaterialProvider;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.MetadataDirective;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.InstructionFileConfig;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.MaterialsDescription;

/**
 * This class is an integration test for verifying compatibility of ciphertexts
 * between V1, V2, and V3 clients under various conditions.
 */
public class S3EncryptionClientCompatibilityTest {

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
    public void AesCbcV1toV3() {
        final String objectKey = appendTestSuffix("aes-cbc-v1-to-v3");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.EncryptionOnly);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                //= specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
                //= type=test
                //# The S3EC MUST support the option to enable or disable legacy wrapping algorithms.
                //= specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
                //= type=test
                //# When enabled, the S3EC MUST be able to decrypt objects encrypted with all supported wrapping algorithms (both legacy and fully supported).
                .enableLegacyWrappingAlgorithms(true)
                //= specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
                //= type=test
                //# The S3EC MUST support the option to enable or disable legacy unauthenticated modes (content encryption algorithms).
                //= specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
                //= type=test
                //# When enabled, the S3EC MUST be able to decrypt objects encrypted with all content encryption algorithms (both legacy and fully supported).
                .enableLegacyUnauthenticatedModes(true)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "AesCbcV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void AesCbcV1toV4() {
        final String objectKey = appendTestSuffix("aes-cbc-v1-to-v4");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.EncryptionOnly);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                //= specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
                //= type=test
                //# The S3EC MUST support the option to enable or disable legacy wrapping algorithms.
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Asserts
        final String input = "AesCbcV1toV4";
        v1Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void AesWrapV1toV3() {
        final String objectKey = appendTestSuffix("aes-wrap-v1-to-v3");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "AesGcmV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void AesWrapV1toV4() {
        final String objectKey = appendTestSuffix("aes-wrap-v1-to-v4");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 Client
        S3Client v4Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .build();

        // Asserts
        final String input = "AesGcmV1toV4";
        v1Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> v4Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build()));

        // Cleanup
        deleteObject(BUCKET, objectKey, v4Client);
        v4Client.close();
    }

    @Test
    public void AesGcmV2toV3() {
        final String objectKey = appendTestSuffix("aes-gcm-v2-to-v3");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "AesGcmV2toV3";
        v2Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();

    }

    @Test
    public void AesGcmV2toV4() {
        final String objectKey = appendTestSuffix("aes-gcm-v2-to-v4");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V4 Client
        S3Client v4Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmV2toV4";
        v2Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> v4Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build()));

        // Cleanup
        deleteObject(BUCKET, objectKey, v4Client);
        v4Client.close();

    }

    @Test
    public void AesGcmV2toV3WithInstructionFile() {
        final String objectKey = appendTestSuffix("aes-gcm-v2-to-v3-with-instruction-file");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfigurationV2 cryptoConfig =
                new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
                        .withStorageMode(CryptoStorageMode.InstructionFile);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCryptoConfiguration(cryptoConfig)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .instructionFileConfig(InstructionFileConfig.builder()
                        .instructionFileClient(S3Client.create())
                        .build())
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "AesGcmV2toV3";
        v2Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(
                GetObjectRequest.builder()
                        .bucket(BUCKET)
                        .key(objectKey).build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void AesGcmV2toV4WithInstructionFile() {
        final String objectKey = appendTestSuffix("aes-gcm-v2-to-v4-with-instruction-file");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfigurationV2 cryptoConfig =
                new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
                        .withStorageMode(CryptoStorageMode.InstructionFile);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCryptoConfiguration(cryptoConfig)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V4 Client
        S3Client v4Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .instructionFileConfig(InstructionFileConfig.builder()
                        .instructionFileClient(S3Client.create())
                        .build())
                .build();

        // Asserts
        final String input = "AesGcmV2toV4";
        v2Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> v4Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build()));

        // Cleanup
        deleteObject(BUCKET, objectKey, v4Client);
        v4Client.close();
    }

    @Test
    public void AesGcmV3toV1() {
        final String objectKey = appendTestSuffix("aes-gcm-v3-to-v1");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "AesGcmV3toV1";
        s3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromString(input));

        String output = v1Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void AesGcmV4toV1Fails() {
        final String objectKey = appendTestSuffix("aes-gcm-v4-to-v1");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmV4toV1";
        s3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromString(input));

        // V1Client in AuthenticatedEncryption decrypts the data first before authenticating the tag and
        // returns BAD plaintext
        String output = v1Client.getObjectAsString(BUCKET, objectKey);
        assertNotEquals(input, output);

        // V1 Client in StrictAuthenticatedEncryption
        v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.StrictAuthenticatedEncryption);
        AmazonS3Encryption v1ClientStrict = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V1Client in StrictAuthenticatedEncryption SHOULD fail to decrypt ciphertext
        assertThrows(SecurityException.class, () -> v1ClientStrict.getObjectAsString(BUCKET, objectKey));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void AesGcmV3toV2() {
        final String objectKey = appendTestSuffix("aes-gcm-v3-to-v2");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "AesGcmV3toV2";
        s3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromString(input));

        String output = v2Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void AesGcmV4toV2Fails() {
        final String objectKey = appendTestSuffix("aes-gcm-v4-to-v2");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V4 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmV4toV2";
        s3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromString(input));

        assertThrows(SecurityException.class, () -> v2Client.getObjectAsString(BUCKET, objectKey));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void AesGcmV3toV3() {
        final String objectKey = appendTestSuffix("aes-gcm-v3-to-v3");

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "AesGcmV3toV3";
        s3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void AesGcmV3toV4FailsWithRequireDecrypt() {
        final String objectKey = appendTestSuffix("aes-gcm-v3-to-v4");

        // V4 - Transition Mode Client
        S3Client s3ClientTransition = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "AesGcmV3toV4";
        s3ClientTransition.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));
        s3ClientTransition.close();

        // V4 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .build();

        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));
        assertTrue(exception.getMessage().contains("Commitment policy violation, decryption requires a committing algorithm suite"));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void AesGcmV4toV4() {
        final String objectKey = appendTestSuffix("aes-gcm-v4-to-v4");

        // V4 Client
        S3Client v4Client = S3EncryptionClient.builderV4()
                //= specification/s3-encryption/client.md#cryptographic-materials
                //= type=test
                //# The S3EC MAY accept key material directly.
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmV4toV4";
        v4Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v4Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v4Client);
        v4Client.close();
    }

    @Test
    public void AesGcmV4toV3() {
        final String objectKey = appendTestSuffix("aes-gcm-v4-to-v3");

        // V4 - Transition Mode Client
        S3Client s3ClientTransition = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // V4 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmV4toV3";
        s3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));
        s3ClientTransition.close();

        ResponseBytes<GetObjectResponse> objectResponse = s3ClientTransition.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void RsaV1toV3() {
        final String objectKey = appendTestSuffix("v1-rsa-to-v3");

        EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .rsaKeyPair(RSA_KEY_PAIR)
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(true)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        final String input = "This is some content to encrypt using the v1 client";
        v1Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void RsaV1toV4Fails() {
        final String objectKey = appendTestSuffix("v1-rsa-to-v4");

        EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 Client
        S3Client v4Client = S3EncryptionClient.builderV4()
                .rsaKeyPair(RSA_KEY_PAIR)
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        final String input = "This is some content to encrypt using the v1 client";
        v1Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> v4Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build()));

        deleteObject(BUCKET, objectKey, v4Client);
        v4Client.close();
    }


    @Test
    public void RsaV1toV3AesFails() {
        final String objectKey = appendTestSuffix("v1-rsa-to-v3-aes-fails");

        EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withEncryptionMaterials(materialsProvider)
                .build();

        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        final String input = "This is some content to encrypt using the v1 client";
        v1Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build()));

        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void RsaEcbV1toV3() {
        final String objectKey = appendTestSuffix("rsa-ecb-v1-to-v3");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .rsaKeyPair(RSA_KEY_PAIR)
                .enableLegacyWrappingAlgorithms(true)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "RsaEcbV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void RsaEcbV1toV4Fails() {
        final String objectKey = appendTestSuffix("rsa-ecb-v1-to-v4");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 Client
        S3Client v4Client = S3EncryptionClient.builderV4()
                .rsaKeyPair(RSA_KEY_PAIR)
                .enableLegacyWrappingAlgorithms(true)
                .build();

        // Asserts
        final String input = "RsaEcbV1toV4";
        v1Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> v4Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build()));

        // Cleanup
        deleteObject(BUCKET, objectKey, v4Client);
        v4Client.close();
    }

    @Test
    public void RsaOaepV2toV3() {
        final String objectKey = appendTestSuffix("rsa-oaep-v2-to-v3");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        CryptoConfigurationV2 cryptoConfig =
                new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCryptoConfiguration(cryptoConfig)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .rsaKeyPair(RSA_KEY_PAIR)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "RsaOaepV2toV3";
        v2Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void RsaOaepV2toV4Fails() {
        final String objectKey = appendTestSuffix("rsa-oaep-v2-to-v4");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        CryptoConfigurationV2 cryptoConfig =
                new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCryptoConfiguration(cryptoConfig)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V4 Client
        S3Client v4Client = S3EncryptionClient.builderV4()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        // Asserts
        final String input = "RsaOaepV2toV4";
        v2Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> v4Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build()));

        // Cleanup
        deleteObject(BUCKET, objectKey, v4Client);
        v4Client.close();
    }

    @Test
    public void RsaOaepV3toV1() {
        final String objectKey = appendTestSuffix("rsa-oaep-v3-to-v1");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 Client - Transition Mode
        S3Client s3Client = S3EncryptionClient.builderV4()
                .rsaKeyPair(RSA_KEY_PAIR)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "RsaOaepV3toV1";
        s3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromString(input));

        String output = v1Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void RsaOaepV3toV2() {
        final String objectKey = appendTestSuffix("rsa-oaep-v3-to-v2");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .rsaKeyPair(RSA_KEY_PAIR)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "RsaOaepV3toV2";
        s3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromString(input));

        String output = v2Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void RsaOaepV4toV2Fails() {
        final String objectKey = appendTestSuffix("rsa-oaep-v4-to-v2");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V4 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        // Asserts
        final String input = "RsaOaepV4toV2";
        s3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromString(input));

        assertThrows(SecurityException.class, () -> v2Client.getObjectAsString(BUCKET, objectKey));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void RsaOaepV3toV3() {
        final String objectKey = appendTestSuffix("rsa-oaep-v3-to-v3");

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .rsaKeyPair(RSA_KEY_PAIR)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "RsaOaepV3toV3";
        s3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void RsaOaepV4toV4() {
        final String objectKey = appendTestSuffix("rsa-oaep-v4-to-v3");

        // V4 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                //= specification/s3-encryption/client.md#cryptographic-materials
                //= type=test
                //# The S3EC MAY accept key material directly.
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        // Asserts
        final String input = "RsaOaepV4toV3";
        s3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void KmsCBCV1ToV3() {
        String objectKey = appendTestSuffix("v1-kms-cbc-to-v3");

        AWSKMS kmsClient = AWSKMSClientBuilder.standard()
                .withRegion(KMS_REGION.toString())
                .build();
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        // v1 Client in default mode
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withEncryptionMaterials(materialsProvider)
                .withKmsClient(kmsClient)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyUnauthenticatedModes(true)
                .enableLegacyWrappingAlgorithms(true)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        String input = "This is some content to encrypt using v1 client";

        v1Client.putObject(BUCKET, objectKey, input);
        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());
        String output = objectResponse.asUtf8String();

        assertEquals(input, output);

        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void KmsCBCV1ToV4Fails() {
        String objectKey = appendTestSuffix("v1-kms-cbc-to-v4");

        AWSKMS kmsClient = AWSKMSClientBuilder.standard()
                .withRegion(KMS_REGION.toString())
                .build();
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        // v1 Client in default mode
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withEncryptionMaterials(materialsProvider)
                .withKmsClient(kmsClient)
                .build();

        // V4 Client
        S3Client v4Client = S3EncryptionClient.builderV4()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyUnauthenticatedModes(true)
                .enableLegacyWrappingAlgorithms(true)
                .build();

        String input = "This is some content to encrypt using v1 client";

        v1Client.putObject(BUCKET, objectKey, input);
        assertThrows(S3EncryptionClientException.class, () -> v4Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build()));

        deleteObject(BUCKET, objectKey, v4Client);
        v4Client.close();
    }

    @Test
    public void KmsV1toV3() {
        final String objectKey = appendTestSuffix("kms-v1-to-v3");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withStorageMode(CryptoStorageMode.InstructionFile)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyWrappingAlgorithms(true)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "KmsV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void KmsV1toV4() {
        final String objectKey = appendTestSuffix("kms-v1-to-v4");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withStorageMode(CryptoStorageMode.InstructionFile)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyWrappingAlgorithms(true)
                .build();

        // Asserts
        final String input = "KmsV1toV4";
        v1Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void KmsContextV2toV3() {
        final String objectKey = appendTestSuffix("kms-context-v2-to-v3");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        CryptoConfigurationV2 config = new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .withCryptoConfiguration(config)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .kmsKeyId(KMS_KEY_ID)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "KmsContextV2toV3";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value");
        EncryptedPutObjectRequest putObjectRequest = new EncryptedPutObjectRequest(
                BUCKET,
                objectKey,
                new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)),
                null
        ).withMaterialsDescription(encryptionContext);
        v2Client.putObject(putObjectRequest);

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext)));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void KmsContextV2toV4Fails() {
        final String objectKey = appendTestSuffix("kms-context-v2-to-v4");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        CryptoConfigurationV2 config = new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .withCryptoConfiguration(config)
                .build();

        // V4 Client
        S3Client v4Client = S3EncryptionClient.builderV4()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // Asserts
        final String input = "KmsContextV2toV4";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value");
        EncryptedPutObjectRequest putObjectRequest = new EncryptedPutObjectRequest(
                BUCKET,
                objectKey,
                new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)),
                null
        ).withMaterialsDescription(encryptionContext);
        v2Client.putObject(putObjectRequest);

        assertThrows(S3EncryptionClientException.class, () -> v4Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext))));

        // Cleanup
        deleteObject(BUCKET, objectKey, v4Client);
        v4Client.close();
    }

    // All Below cases should expect failure, since we're writing with V3 Message Format
    @Test
    public void KmsContextV3toV1() {
        final String objectKey = appendTestSuffix("kms-context-v3-to-v1");

        // V1 Client
        KMSEncryptionMaterials kmsMaterials = new KMSEncryptionMaterials(KMS_KEY_ID);
        kmsMaterials.addDescription("user-metadata-key", "user-metadata-value-v3-to-v1");
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(kmsMaterials);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .kmsKeyId(KMS_KEY_ID)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "KmsContextV3toV1";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v1");

        s3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext)), RequestBody.fromString(input));

        String output = v1Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, output);


        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }


    @Test
    public void KmsContextV4toV1Fails() {
        final String objectKey = appendTestSuffix("kms-context-v4-to-v1");

        // V1 Client
        KMSEncryptionMaterials kmsMaterials = new KMSEncryptionMaterials(KMS_KEY_ID);
        kmsMaterials.addDescription("user-metadata-key", "user-metadata-value-v4-to-v1");
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(kmsMaterials);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // Asserts
        final String input = "KmsContextV4toV1";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v4-to-v1");

        s3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext)), RequestBody.fromString(input));


        // V1Client in AuthenticatedEncryption decrypts the data first before authenticating the tag and
        // returns BAD plaintext
        String output = v1Client.getObjectAsString(BUCKET, objectKey);
        assertNotEquals(input, output);

        // V1 Client in StrictAuthenticatedEncryption
        v1Config =
                new CryptoConfiguration(CryptoMode.StrictAuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1ClientStrict = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V1Client in StrictAuthenticatedEncryption SHOULD fail to decrypt ciphertext
        assertThrows(SecurityException.class, () -> v1ClientStrict.getObjectAsString(BUCKET, objectKey));


        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void KmsContextV3toV2() throws IOException {
        final String objectKey = appendTestSuffix("kms-context-v3-to-v2");

        // V2 Client
        KMSEncryptionMaterials kmsMaterials = new KMSEncryptionMaterials(KMS_KEY_ID);
        kmsMaterials.addDescription("user-metadata-key", "user-metadata-value-v3-to-v2");
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(kmsMaterials);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .kmsKeyId(KMS_KEY_ID)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "KmsContextV3toV2";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v2");

        s3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .overrideConfiguration(withAdditionalConfiguration(encryptionContext)),
                RequestBody.fromString(input));

        String output = v2Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, output);
        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void KmsContextV4toV2Fails() throws IOException {
        final String objectKey = appendTestSuffix("kms-context-v4-to-v2");

        // V2 Client
        KMSEncryptionMaterials kmsMaterials = new KMSEncryptionMaterials(KMS_KEY_ID);
        kmsMaterials.addDescription("user-metadata-key", "user-metadata-value-v4-to-v2");
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(kmsMaterials);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V4 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // Asserts
        final String input = "KmsContextV4toV2";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v4-to-v2");

        s3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .overrideConfiguration(withAdditionalConfiguration(encryptionContext)),
                RequestBody.fromString(input));

        assertThrows(SecurityException.class, () -> v2Client.getObjectAsString(BUCKET, objectKey));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void KmsContextV3toV3() {
        final String objectKey = appendTestSuffix("kms-context-v3-to-v3");

        // V4 - Transition Mode Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .kmsKeyId(KMS_KEY_ID)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        // Asserts
        final String input = "KmsContextV3toV3";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        s3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .overrideConfiguration(withAdditionalConfiguration(encryptionContext)),
                RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext)));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void KmsContextV4toV4() {
        final String objectKey = appendTestSuffix("kms-context-v4-to-v3");

        // V4 Client
        S3Client v4Client = S3EncryptionClient.builderV4()
                //= specification/s3-encryption/client.md#cryptographic-materials
                //= type=test
                //# The S3EC MAY accept key material directly.
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // Asserts
        final String input = "KmsContextV4toV3";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v4-to-v3");

        v4Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .overrideConfiguration(withAdditionalConfiguration(encryptionContext)),
                RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v4Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext)));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v4Client);
        v4Client.close();
    }

    @Test
    public void KmsContextV3toV3MismatchFails() {
        final String objectKey = appendTestSuffix("kms-context-v3-to-v3");

        // V3 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // Asserts
        final String input = "KmsContextV3toV3";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        s3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .overrideConfiguration(withAdditionalConfiguration(encryptionContext)),
                RequestBody.fromString(input));

        // Use the wrong EC
        Map<String, String> otherEncryptionContext = new HashMap<>();
        otherEncryptionContext.put("user-metadata-key", "!user-metadata-value-v3-to-v3");

        assertThrows(S3EncryptionClientException.class, () -> s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalConfiguration(otherEncryptionContext))));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }


    @Test
    public void AesCbcV1toV3FailsWhenLegacyModeDisabled() {
        final String objectKey = appendTestSuffix("aes-cbc-v1-to-v3");

        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.EncryptionOnly);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(false)
                .enableLegacyUnauthenticatedModes(false)
                .build();

        final String input = "AesCbcV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        //= specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
        //= type=test
        //# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy content encryption algorithms; it MUST throw an exception when attempting to decrypt an object encrypted with a legacy content encryption algorithm.
        //= specification/s3-encryption/decryption.md#legacy-decryption
        //= type=test
        //# The S3EC MUST NOT decrypt objects encrypted using legacy unauthenticated algorithm suites unless specifically configured to do so.
        //= specification/s3-encryption/decryption.md#legacy-decryption
        //= type=test
        //# If the S3EC is not configured to enable legacy unauthenticated content decryption, the client MUST throw an exception when attempting to decrypt an object encrypted with a legacy unauthenticated algorithm suite.
        assertThrows(S3EncryptionClientException.class, () -> s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void AesCbcV1toV3FailsWhenUnauthencticateModeDisabled() {
        final String objectKey = appendTestSuffix("fails-aes-cbc-v1-to-v3-when-unauthencticate-mode-disabled");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.EncryptionOnly);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V4 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                //= specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
                //= type=test
                //# The option to enable legacy unauthenticated modes MUST be set to false by default.
                //.enableLegacyUnauthenticatedModes(false)
                .build();

        // Asserts
        final String input = "AesCbcV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        //= specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
        //= type=test
        //# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy wrapping algorithms; it MUST throw an exception when attempting to decrypt an object encrypted with a legacy wrapping algorithm.
        assertThrows(S3EncryptionClientException.class, () -> s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void AesCbcV1toV3FailsWhenLegacyKeyringDisabled() {
        final String objectKey = appendTestSuffix("fails-aes-cbc-v1-to-v3-when-legacy-keyring-disabled");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.EncryptionOnly);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V3 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                //= specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
                //= type=test
                //# The option to enable legacy wrapping algorithms MUST be set to false by default.
                //.enableLegacyWrappingAlgorithms(false)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Asserts
        final String input = "AesCbcV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        //= specification/s3-encryption/client.md#enable-legacy-wrapping-algorithms
        //= type=test
        //# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy wrapping algorithms; it MUST throw an exception when attempting to decrypt an object encrypted with a legacy wrapping algorithm.
        assertThrows(S3EncryptionClientException.class, () -> s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void AesWrapV1toV3FailsWhenLegacyModeDisabled() {
        final String objectKey = appendTestSuffix("aes-wrap-v1-to-v3");

        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        S3Client s3Client = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(false)
                .build();

        final String input = "AesGcmV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void nullMaterialDescriptionV3() {
        final String objectKey = appendTestSuffix("null-matdesc-v3");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V4 Transition Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmWithNullMatDesc";
        v2Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Now remove MatDesc - this must be done via CopyObject
        final String copyKey = objectKey + "copied";
        Map<String, String> modMd = new HashMap<>(objectResponse.response().metadata());
        modMd.remove("x-amz-meta-x-amz-matdesc");
        modMd.remove("x-amz-matdesc");
        s3Client.copyObject(builder -> builder
                .sourceBucket(BUCKET)
                .destinationBucket(BUCKET)
                .sourceKey(objectKey)
                .destinationKey(copyKey)
                .metadataDirective(MetadataDirective.REPLACE)
                .metadata(modMd)
                .build());

        // V2
        String v2CopyOut = v2Client.getObjectAsString(BUCKET, copyKey);
        assertEquals(input, v2CopyOut);

        // V3
        ResponseBytes<GetObjectResponse> objectResponseCopy = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(copyKey));
        String outputCopy = objectResponseCopy.asUtf8String();
        assertEquals(input, outputCopy);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        deleteObject(BUCKET, copyKey, s3Client);
        s3Client.close();

    }
}
