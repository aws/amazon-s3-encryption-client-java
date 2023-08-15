// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
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
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

/**
 * This class is an integration test for verifying compatibility of ciphertexts
 * between V1, V2, and V3 clients under various conditions.
 */
public class S3EncryptionClientCompatibilityTest {

    private static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");
    private static final String KMS_KEY_ID = System.getenv("AWS_S3EC_TEST_KMS_KEY_ID");
    private static final Region KMS_REGION = Region.getRegion(Regions.fromName(System.getenv("AWS_REGION")));

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

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Asserts
        final String input = "AesCbcV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .build();

        // Asserts
        final String input = "AesGcmV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmV2toV3";
        v2Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmV2toV3";
        v2Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(
                GetObjectRequest.builder()
                        .bucket(BUCKET)
                        .key(objectKey).build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmV3toV1";
        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromString(input));

        String output = v1Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmV3toV2";
        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromString(input));

        String output = v2Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void AesGcmV3toV3() {
        final String objectKey = appendTestSuffix("aes-gcm-v3-to-v3");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmV3toV3";
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void RsaV1toV3() {
        final String objectKey = appendTestSuffix("v1-rsa-to-v3");

        EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withEncryptionMaterials(materialsProvider)
                .build();

        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        final String input = "This is some content to encrypt using the v1 client";
        v1Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }


    @Test
    public void RsaV1toV3AesFails() {
        final String objectKey = appendTestSuffix("v1-rsa-to-v3-aes-fails");

        EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withEncryptionMaterials(materialsProvider)
                .build();

        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        final String input = "This is some content to encrypt using the v1 client";
        v1Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build()));

        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .enableLegacyWrappingAlgorithms(true)
                .build();

        // Asserts
        final String input = "RsaEcbV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        // Asserts
        final String input = "RsaOaepV2toV3";
        v2Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        // Asserts
        final String input = "RsaOaepV3toV1";
        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromString(input));

        String output = v1Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        // Asserts
        final String input = "RsaOaepV3toV2";
        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromString(input));

        String output = v2Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void RsaOaepV3toV3() {
        final String objectKey = appendTestSuffix("rsa-oaep-v3-to-v3");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        // Asserts
        final String input = "RsaOaepV3toV3";
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyUnauthenticatedModes(true)
                .enableLegacyWrappingAlgorithms(true)
                .build();

        String input = "This is some content to encrypt using v1 client";

        v1Client.putObject(BUCKET, objectKey, input);
        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());
        String output = objectResponse.asUtf8String();

        assertEquals(input, output);

        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void KmsV1toV3() {
        final String objectKey = appendTestSuffix("kms-v1-to-v3");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyWrappingAlgorithms(true)
                .build();

        // Asserts
        final String input = "KmsV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void KmsContextV2toV3() {
        final String objectKey = appendTestSuffix("kms-context-v2-to-v3");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
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

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext)));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

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

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // Asserts
        final String input = "KmsContextV3toV1";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v1");

        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext)), RequestBody.fromString(input));

        String output = v1Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // Asserts
        final String input = "KmsContextV3toV2";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v2");

        v3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .overrideConfiguration(withAdditionalConfiguration(encryptionContext)),
                RequestBody.fromString(input));

        String output = v2Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void KmsContextV3toV3() {
        final String objectKey = appendTestSuffix("kms-context-v3-to-v3");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // Asserts
        final String input = "KmsContextV3toV3";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        v3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .overrideConfiguration(withAdditionalConfiguration(encryptionContext)),
                RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext)));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void KmsContextV3toV3MismatchFails() {
        final String objectKey = appendTestSuffix("kms-context-v3-to-v3");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // Asserts
        final String input = "KmsContextV3toV3";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        v3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .overrideConfiguration(withAdditionalConfiguration(encryptionContext)),
                RequestBody.fromString(input));

        // Use the wrong EC
        Map<String, String> otherEncryptionContext = new HashMap<>();
        otherEncryptionContext.put("user-metadata-key", "!user-metadata-value-v3-to-v3");

        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalConfiguration(otherEncryptionContext))));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(false)
                .enableLegacyUnauthenticatedModes(false)
                .build();

        final String input = "AesCbcV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(false)
                .build();

        // Asserts
        final String input = "AesCbcV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(false)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Asserts
        final String input = "AesCbcV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(false)
                .build();

        final String input = "AesGcmV1toV3";
        v1Client.putObject(BUCKET, objectKey, input);

        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }
}
