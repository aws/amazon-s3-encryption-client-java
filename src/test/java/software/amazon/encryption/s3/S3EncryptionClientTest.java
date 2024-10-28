// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.CryptoConfigurationV2;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.KMSEncryptionMaterials;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.NoSuchUploadException;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.encryption.s3.internal.InstructionFileConfig;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DefaultCryptoMaterialsManager;
import software.amazon.encryption.s3.materials.KmsKeyring;
import software.amazon.encryption.s3.utils.BoundedInputStream;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.ALTERNATE_BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.ALTERNATE_KMS_KEY;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ALIAS;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_REGION;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

/**
 * This class is an integration test for verifying behavior of the V3 client
 * under various scenarios.
 */
public class S3EncryptionClientTest {

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
    public void copyObjectTransparently() {
        final String objectKey = appendTestSuffix("copy-object-from-here");
        final String newObjectKey = appendTestSuffix("copy-object-to-here");

        S3Client s3EncryptionClient = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        final String input = "SimpleTestOfV3EncryptionClientCopyObject";

        s3EncryptionClient.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build(),
                RequestBody.fromString(input));

        s3EncryptionClient.copyObject(builder -> builder
                .sourceBucket(BUCKET)
                .destinationBucket(BUCKET)
                .sourceKey(objectKey)
                .destinationKey(newObjectKey)
                .build());

        ResponseBytes<GetObjectResponse> objectResponse = s3EncryptionClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(newObjectKey)
                .build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3EncryptionClient);
        deleteObject(BUCKET, newObjectKey, s3EncryptionClient);
        s3EncryptionClient.close();
    }

    @Test
    public void deleteObjectWithInstructionFileSuccess() {
        final String objectKey = appendTestSuffix("delete-object-with-instruction-file");

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
        final String input = "DeleteObjectWithInstructionFileSuccess";
        v2Client.putObject(BUCKET, objectKey, input);

        // Delete Object
        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));

        S3Client s3Client = S3Client.builder().build();
        // Assert throw NoSuchKeyException when getObject for objectKey
        assertThrows(S3Exception.class, () -> s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));
        assertThrows(S3Exception.class, () -> s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey + ".instruction")));

        // Cleanup
        v3Client.close();
        s3Client.close();
    }

    @Test
    public void deleteObjectsWithInstructionFilesSuccess() {
        final String[] objectKeys = {appendTestSuffix("delete-object-with-instruction-file-1"),
                appendTestSuffix("delete-object-with-instruction-file-2"),
                appendTestSuffix("delete-object-with-instruction-file-3")};

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
        final String input = "DeleteObjectsWithInstructionFileSuccess";
        List<ObjectIdentifier> objects = new ArrayList<>();
        for (String objectKey : objectKeys) {
            v2Client.putObject(BUCKET, objectKey, input);
            objects.add(ObjectIdentifier.builder().key(objectKey).build());
        }

        // Delete Objects from S3 Buckets
        v3Client.deleteObjects(builder -> builder
                .bucket(BUCKET)
                .delete(builder1 -> builder1.objects(objects)));

        S3Client s3Client = S3Client.builder().build();
        // Assert throw NoSuchKeyException when getObject for any of objectKeys
        assertThrows(S3Exception.class, () -> s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKeys[0])));
        assertThrows(S3Exception.class, () -> s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKeys[0] + ".instruction")));

        // Cleanup
        v3Client.close();
        s3Client.close();
    }

    @Test
    public void deleteObjectWithWrongObjectKeySuccess() {
        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        assertDoesNotThrow(() -> v3Client.deleteObject(builder -> builder.bucket(BUCKET).key("InvalidKey")));

        // Cleanup
        v3Client.close();
    }

    @Test
    public void deleteObjectWithWrongBucketFailure() {
        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        try {
            v3Client.deleteObject(builder -> builder.bucket("NotMyBukkit").key("InvalidKey"));
        } catch (S3EncryptionClientException exception) {
            // Verify inner exception
            assertTrue(exception.getCause() instanceof NoSuchBucketException);
        }

        v3Client.close();
    }

    @Test
    public void deleteObjectsWithWrongBucketFailure() {
        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        List<ObjectIdentifier> objects = new ArrayList<>();
        objects.add(ObjectIdentifier.builder().key("InvalidKey").build());
        try {
            v3Client.deleteObjects(builder -> builder.bucket("NotMyBukkit").delete(builder1 -> builder1.objects(objects)));
        } catch (S3EncryptionClientException exception) {
            // Verify inner exception
            assertTrue(exception.getCause() instanceof NoSuchBucketException);
        }
        v3Client.close();
    }

    @Test
    public void getNonExistentObject() {
        final String objectKey = appendTestSuffix("this-is-not-an-object-key");
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ALIAS)
                .build();

        // Ensure the object does not exist
        deleteObject(BUCKET, objectKey, v3Client);

        try {
            v3Client.getObjectAsBytes(builder -> builder
                    .bucket(BUCKET)
                    .key(objectKey)
                    .build());
        } catch (S3EncryptionClientException exception) {
            // Depending on the permissions of the calling principal,
            // this could be NoSuchKeyException
            // or S3Exception (access denied)
            assertTrue(exception.getCause() instanceof S3Exception);
        }

        // Cleanup
        v3Client.close();
    }

    @Test
    public void s3EncryptionClientWithMultipleKeyringsFails() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .rsaKeyPair(RSA_KEY_PAIR)
                .build());
    }

    @Test
    public void s3EncryptionClientWithNoKeyringsFails() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .build());
    }

    @Test
    public void s3EncryptionClientWithNoLegacyKeyringsFails() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .enableLegacyWrappingAlgorithms(true)
                .build());
    }

    @Test
    public void KmsWithAliasARN() {
        final String objectKey = appendTestSuffix("kms-with-alias-arn");
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ALIAS)
                .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void KmsWithShortKeyId() {
        final String objectKey = appendTestSuffix("kms-with-short-key-id");
        // Just assume the ARN is well-formed
        // Also assume that the region is set correctly
        final String shortId = KMS_KEY_ID.split("/")[1];

        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(shortId)
                .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void KmsAliasARNToKeyId() {
        final String objectKey = appendTestSuffix("kms-alias-arn-to-key-id");
        S3Client aliasClient = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ALIAS)
                .build();

        S3Client keyIdClient = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        final String input = "KmsAliasARNToKeyId";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-alias-to-id");

        aliasClient.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .overrideConfiguration(withAdditionalConfiguration(encryptionContext)),
                RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = keyIdClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext)));
        String output = objectResponse.asUtf8String();

        assertEquals(input, output);
        deleteObject(BUCKET, objectKey, aliasClient);
        aliasClient.close();
        keyIdClient.close();
    }

    @Test
    public void AesKeyringWithInvalidAesKey() throws NoSuchAlgorithmException {
        SecretKey invalidAesKey;
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        invalidAesKey = keyGen.generateKey();

        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .aesKey(invalidAesKey)
                .build());
    }

    @Test
    public void RsaKeyringWithInvalidRsaKey() throws NoSuchAlgorithmException {
        KeyPair invalidRsaKey;
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256);
        invalidRsaKey = keyPairGen.generateKeyPair();

        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .rsaKeyPair(invalidRsaKey)
                .build());
    }

    @Test
    public void s3EncryptionClientWithKeyringFromKmsKeyIdSucceeds() {
        final String objectKey = appendTestSuffix("keyring-from-kms-key-id");

        KmsKeyring keyring = KmsKeyring.builder().wrappingKeyId(KMS_KEY_ID).build();

        S3Client v3Client = S3EncryptionClient.builder()
                .keyring(keyring)
                .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void s3EncryptionClientWithCmmFromKmsKeyIdSucceeds() {
        final String objectKey = appendTestSuffix("cmm-from-kms-key-id");

        KmsKeyring keyring = KmsKeyring.builder().wrappingKeyId(KMS_KEY_ID).build();

        CryptographicMaterialsManager cmm = DefaultCryptoMaterialsManager.builder()
                .keyring(keyring)
                .build();

        S3Client v3Client = S3EncryptionClient.builder()
                .cryptoMaterialsManager(cmm)
                .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void s3EncryptionClientWithWrappedS3ClientSucceeds() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-kms-key-id");

        S3Client wrappedClient = S3Client.create();
        S3AsyncClient wrappedAsyncClient = S3AsyncClient.create();

        S3Client wrappingClient = S3EncryptionClient.builder()
                .wrappedClient(wrappedClient)
                .wrappedAsyncClient(wrappedAsyncClient)
                .kmsKeyId(KMS_KEY_ID)
                .build();

        simpleV3RoundTrip(wrappingClient, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, wrappingClient);
        wrappedClient.close();
        wrappedAsyncClient.close();
        wrappingClient.close();
    }

    /**
     * S3EncryptionClient implements S3Client, so it can be passed into the builder as a wrappedClient.
     * However, is not a supported use case, and the builder should throw an exception if this happens.
     */
    @Test
    public void s3EncryptionClientWithWrappedS3EncryptionClientFails() {
        S3AsyncClient wrappedAsyncClient = S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .wrappedAsyncClient(wrappedAsyncClient)
                .kmsKeyId(KMS_KEY_ID)
                .build());
    }

    @Test
    public void s3EncryptionClientWithNullSecureRandomFails() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .secureRandom(null)
                .build());
    }

    @Test
    public void s3EncryptionClientFromKMSKeyDoesNotUseUnprovidedSecureRandom() {
        SecureRandom mockSecureRandom = mock(SecureRandom.class, withSettings().withoutAnnotations());

        final String objectKey = appendTestSuffix("no-secure-random-object-kms");

        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        simpleV3RoundTrip(v3Client, objectKey);

        verify(mockSecureRandom, never()).nextBytes(any());

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void cryptoProviderV3toV3Enabled() {
        final String objectKey = appendTestSuffix("crypto-provider-enabled-v3-to-v3");

        Security.addProvider(new BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .cryptoProvider(provider)
                .build();

        final String input = "CryptoProviderEnabled";
        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromString(input));

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
    public void cryptoProviderV2toV3Enabled() {
        final String objectKey = appendTestSuffix("crypto-provider-enabled-v2-to-v3");

        Security.addProvider(new BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");

        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfigurationV2 v2Config = new CryptoConfigurationV2()
                .withCryptoProvider(provider)
                .withAlwaysUseCryptoProvider(true);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .withCryptoConfiguration(v2Config)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .cryptoProvider(provider)
                .build();

        final String input = "CryptoProviderEnabled";
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
    public void contentLengthRequest() {
        final String objectKey = appendTestSuffix("content-length");

        S3Client s3EncryptionClient = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        final String input = "SimpleTestOfV3EncryptionClientCopyObject";
        final int inputLength = input.length();

        s3EncryptionClient.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .contentLength((long) inputLength)
                        .build(),
                RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = s3EncryptionClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3EncryptionClient);
        s3EncryptionClient.close();
    }

    @Test
    public void attemptToDecryptPlaintext() {
        final String objectKey = appendTestSuffix("plaintext-object");

        final S3Client plaintextS3Client = S3Client.builder().build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        final String input = "SomePlaintext";
        plaintextS3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        try {
            v3Client.getObject(builder -> builder
                    .bucket(BUCKET)
                    .key(objectKey));
            fail("expected exception");
        } catch (S3EncryptionClientException ex) {
            System.out.println(ex.getMessage());
            assertTrue(ex.getMessage().contains("Instruction file not found!"));
            assertEquals(ex.getCause().getClass(), S3EncryptionClientException.class);
        }

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void createMultipartUploadFailure() {
        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        try {
            v3Client.createMultipartUpload(builder -> builder.bucket("NotMyBukkit").key("InvalidKey").build());
        } catch (S3EncryptionClientException exception) {
            // Verify inner exception
            assertInstanceOf(NoSuchBucketException.class, exception.getCause());
        }

        v3Client.close();
    }

    @Test
    public void uploadPartFailure() {
        final String objectKey = appendTestSuffix("upload-part-failure");
        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // To get a server-side failure from uploadPart,
        // a valid MPU request must be created
        CreateMultipartUploadResponse initiateResult = v3Client.createMultipartUpload(builder ->
                builder.bucket(BUCKET).key(objectKey));

        try {
            v3Client.uploadPart(builder -> builder.partNumber(1).bucket("NotMyBukkit").key("InvalidKey").uploadId(initiateResult.uploadId()).build(),
                    RequestBody.fromInputStream(new BoundedInputStream(16), 16));
        } catch (S3EncryptionClientException exception) {
            // Verify inner exception
            assertInstanceOf(NoSuchBucketException.class, exception.getCause());
        }

        // MPU was not completed, but abort and delete to be safe
        v3Client.abortMultipartUpload(builder -> builder.bucket(BUCKET).key(objectKey).uploadId(initiateResult.uploadId()).build());
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void completeMultipartUploadFailure() {
        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        try {
            v3Client.completeMultipartUpload(builder -> builder.bucket("NotMyBukkit").key("InvalidKey").uploadId("Invalid").build());
        } catch (S3EncryptionClientException exception) {
            // Verify inner exception
            assertInstanceOf(NoSuchBucketException.class, exception.getCause());
        }

        v3Client.close();
    }

    @Test
    public void abortMultipartUploadFailure() {
        final String objectKey = appendTestSuffix("abort-multipart-failure");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        try {
            v3Client.abortMultipartUpload(builder -> builder.bucket(BUCKET).key(objectKey).uploadId("invalid upload id").build());
        } catch (S3EncryptionClientException exception) {
            // Verify inner exception
            assertInstanceOf(NoSuchUploadException.class, exception.getCause());
        }

        v3Client.close();
    }

    @Test
    public void s3EncryptionClientWithCustomCredentials() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-custom-credentials");

        // use the default creds, but through an explicit credentials provider
        AwsCredentialsProvider creds = DefaultCredentialsProvider.create();

        S3Client wrappedClient = S3Client
                .builder()
                .credentialsProvider(creds)
                .build();
        S3AsyncClient wrappedAsyncClient = S3AsyncClient
                .builder()
                .credentialsProvider(creds)
                .build();
        KmsClient kmsClient = KmsClient
                .builder()
                .credentialsProvider(creds)
                .build();

        KmsKeyring keyring = KmsKeyring
                .builder()
                .kmsClient(kmsClient)
                .wrappingKeyId(KMS_KEY_ID)
                .build();
        S3Client s3Client = S3EncryptionClient.builder()
                .wrappedClient(wrappedClient)
                .wrappedAsyncClient(wrappedAsyncClient)
                .keyring(keyring)
                .build();

        simpleV3RoundTrip(s3Client, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        wrappedClient.close();
        wrappedAsyncClient.close();
        s3Client.close();
    }

    @Test
    public void s3EncryptionClientTopLevelAllOptions() {
        final String objectKey = appendTestSuffix("s3-client-with-all-top-level-options");
        AwsCredentialsProvider creds = DefaultCredentialsProvider.create();
        // use all top-level options;
        // there isn't a good way to validate every option.
        S3Client s3Client = S3EncryptionClient.builder()
                .credentialsProvider(creds)
                .region(Region.of(KMS_REGION.toString()))
                .kmsKeyId(KMS_KEY_ID)
                .dualstackEnabled(null)
                .fipsEnabled(null)
                .overrideConfiguration(ClientOverrideConfiguration.builder().build()) // null is ambiguous
                .endpointOverride(null)
                .serviceConfiguration(S3Configuration.builder().build()) // null is ambiguous
                .accelerate(null)
                .disableMultiRegionAccessPoints(null)
                .forcePathStyle(null)
                .useArnRegion(null)
                .httpClient(null)
                .httpClientBuilder(null)
                .asyncHttpClient(null)
                .asyncHttpClientBuilder(null)
                .build();

        simpleV3RoundTrip(s3Client, objectKey);

        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void s3EncryptionClientTopLevelCredentials() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-top-level-credentials");

        // use the default creds, but through an explicit credentials provider
        AwsCredentialsProvider creds = DefaultCredentialsProvider.create();

        S3Client s3Client = S3EncryptionClient.builder()
                .credentialsProvider(creds)
                .region(Region.of(KMS_REGION.toString()))
                .kmsKeyId(KMS_KEY_ID)
                .build();

        simpleV3RoundTrip(s3Client, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void s3EncryptionClientTopLevelCredentialsWrongRegion() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-top-level-credentials");

        // use the default creds, but through an explicit credentials provider
        AwsCredentialsProvider creds = DefaultCredentialsProvider.create();

        S3Client s3Client = S3EncryptionClient.builder()
                .credentialsProvider(creds)
                .region(Region.of("eu-west-1"))
                .kmsKeyId(KMS_KEY_ID)
                .build();

        try {
            simpleV3RoundTrip(s3Client, objectKey);
            fail("expected exception");
        } catch (S3EncryptionClientException exception) {
            // expected
            assertTrue(exception.getMessage().contains("Invalid arn"));
        } finally {
            // Cleanup
            s3Client.close();
        }
    }

    @Test
    public void s3EncryptionClientTopLevelCredentialsNullCreds() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-null-credentials");

        AwsCredentialsProvider creds = new S3EncryptionClientTestResources.NullCredentialsProvider();

        S3Client s3Client = S3EncryptionClient.builder()
                .credentialsProvider(creds)
                .region(Region.of(KMS_REGION.toString()))
                .kmsKeyId(KMS_KEY_ID)
                .build();

        try {
            simpleV3RoundTrip(s3Client, objectKey);
            fail("expected exception");
        } catch (S3EncryptionClientException exception) {
            // expected
            assertTrue(exception.getMessage().contains("Access key ID cannot be blank"));
        } finally {
            // Cleanup
            s3Client.close();
        }
    }

    @Test
    public void s3EncryptionClientTopLevelAlternateCredentials() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-top-level-credentials");

        // use alternate creds
        AwsCredentialsProvider creds = new S3EncryptionClientTestResources.AlternateRoleCredentialsProvider();

        S3Client s3Client = S3EncryptionClient.builder()
                .credentialsProvider(creds)
                .region(Region.of(KMS_REGION.toString()))
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // using the original key fails
        try {
            simpleV3RoundTrip(s3Client, objectKey);
            fail("expected exception");
        } catch (S3EncryptionClientException exception) {
            // expected
            assertTrue(exception.getMessage().contains("is not authorized to perform"));
            assertInstanceOf(KmsException.class, exception.getCause());
        } finally {
            s3Client.close();
        }

        // using the alternate key succeeds
        S3Client s3ClientAltCreds = S3EncryptionClient.builder()
                .credentialsProvider(creds)
                .region(Region.of(KMS_REGION.toString()))
                .kmsKeyId(ALTERNATE_KMS_KEY)
                .build();

        simpleV3RoundTrip(s3ClientAltCreds, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3ClientAltCreds);
        s3ClientAltCreds.close();
    }

    @Test
    public void s3EncryptionClientMixedCredentials() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-mixed-credentials");

        // use alternate creds for KMS,
        // default for S3
        AwsCredentialsProvider creds = new S3EncryptionClientTestResources.AlternateRoleCredentialsProvider();
        KmsClient kmsClient = KmsClient.builder()
                .credentialsProvider(creds)
                .region(Region.of(KMS_REGION.toString()))
                .build();
        KmsKeyring kmsKeyring = KmsKeyring.builder()
                .kmsClient(kmsClient)
                .wrappingKeyId(ALTERNATE_KMS_KEY)
                .build();

        S3Client s3Client = S3EncryptionClient.builder()
                .keyring(kmsKeyring)
                .build();

        simpleV3RoundTrip(s3Client, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
        kmsClient.close();
    }

    @Test
    public void s3EncryptionClientMixedCredentialsInstructionFile() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-mixed-credentials-instruction-file");
        final String input = "SimpleTestOfV3EncryptionClient";

        // use alternate creds for KMS
        AwsCredentialsProvider creds = new S3EncryptionClientTestResources.AlternateRoleCredentialsProvider();
        S3Client instFileClient = S3Client.builder()
                .credentialsProvider(creds)
                .build();
        S3Client s3Client = S3EncryptionClient.builder()
                .credentialsProvider(creds)
                .instructionFileConfig(InstructionFileConfig.builder()
                        .instructionFileClient(instFileClient)
                        .build())
                .kmsKeyId(ALTERNATE_KMS_KEY)
                .build();

        // use alternate creds for S3
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new KMSEncryptionMaterials(ALTERNATE_KMS_KEY));
        CryptoConfigurationV2 cryptoConfig =
                new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
                        .withStorageMode(CryptoStorageMode.InstructionFile);
        AwsSessionCredentials sdkV2Creds = (AwsSessionCredentials) creds.resolveCredentials();
        AWSCredentials sdkV1Creds = new BasicSessionCredentials(sdkV2Creds.accessKeyId(), sdkV2Creds.secretAccessKey(), sdkV2Creds.sessionToken());
        AWSCredentialsProvider sdkV1Provider = new AWSStaticCredentialsProvider(sdkV1Creds);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCredentials(sdkV1Provider)
                .withCryptoConfiguration(cryptoConfig)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        v2Client.putObject(ALTERNATE_BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(ALTERNATE_BUCKET)
                .key(objectKey)
                .build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(ALTERNATE_BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void s3EncryptionClientMixedCredentialsInstructionFileFails() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-mixed-credentials-instruction-file-fails");
        final String input = "SimpleTestOfV3EncryptionClient";

        // use alternate creds for KMS
        AwsCredentialsProvider creds = new S3EncryptionClientTestResources.AlternateRoleCredentialsProvider();
        S3Client s3Client = S3EncryptionClient.builder()
                .credentialsProvider(creds)
                .kmsKeyId(ALTERNATE_KMS_KEY)
                .build();

        // use alternate creds for S3
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new KMSEncryptionMaterials(ALTERNATE_KMS_KEY));
        CryptoConfigurationV2 cryptoConfig =
                new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
                        .withStorageMode(CryptoStorageMode.InstructionFile);
        AwsSessionCredentials sdkV2Creds = (AwsSessionCredentials) creds.resolveCredentials();
        AWSCredentials sdkV1Creds = new BasicSessionCredentials(sdkV2Creds.accessKeyId(), sdkV2Creds.secretAccessKey(), sdkV2Creds.sessionToken());
        AWSCredentialsProvider sdkV1Provider = new AWSStaticCredentialsProvider(sdkV1Creds);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCredentials(sdkV1Provider)
                .withCryptoConfiguration(cryptoConfig)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        v2Client.putObject(ALTERNATE_BUCKET, objectKey, input);

        // Default creds should fail
        S3Client s3ClientDefault = S3EncryptionClient.builder()
                .kmsKeyId(ALTERNATE_KMS_KEY)
                .build();
        try {
            s3ClientDefault.getObjectAsBytes(builder -> builder
                    .bucket(ALTERNATE_BUCKET)
                    .key(objectKey)
                    .build());
            fail("expected exception");
        } catch (S3EncryptionClientException e) {
            // expected
        }

        // Cleanup
        deleteObject(ALTERNATE_BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void NonUSASCIIMetadataFails() {
        final String objectKey = appendTestSuffix("non-us-ascii-metadata-fails");
        final String input = "This is a test.";
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ALIAS)
                .build();

        Map<String, String> ec = new HashMap<>(1);
        ec.put("ec-key", "我的源资源");
        try {
            v3Client.putObject(builder -> builder
                    .bucket(BUCKET)
                    .key(objectKey)
                    .overrideConfiguration(withAdditionalConfiguration(ec))
                    .build(), RequestBody.fromString(input));
        } catch (S3EncryptionClientException exception) {
            // The Java SDK does not support writing object metadata
            // with non-US-ASCII characters.
            assertTrue(exception.getCause() instanceof S3Exception);
        }

        // Cleanup
        v3Client.close();
    }

    @Test
    public void testInstructionFileConfig() {
        final String objectKey = appendTestSuffix("instruction-file-config");
        final String input = "SimpleTestOfV3EncryptionClient";

        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new KMSEncryptionMaterials(KMS_KEY_ID));
        CryptoConfigurationV2 cryptoConfig =
                new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
                        .withStorageMode(CryptoStorageMode.InstructionFile);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCryptoConfiguration(cryptoConfig)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        v2Client.putObject(BUCKET, objectKey, input);

        S3Client s3ClientDisabledInstructionFile = S3EncryptionClient.builder()
                .instructionFileConfig(InstructionFileConfig.builder()
                        .disableInstructionFile(true)
                        .instructionFileClient(S3Client.create())
                        .build())
                .kmsKeyId(KMS_KEY_ID)
                .build();

        try {
            s3ClientDisabledInstructionFile.getObjectAsBytes(builder -> builder
                    .bucket(BUCKET)
                    .key(objectKey)
                    .build());
            fail("expected exception");
        } catch (S3EncryptionClientException exception) {
            assertTrue(exception.getMessage().contains("Instruction file not found!"));
        }

        S3Client s3Client = S3EncryptionClient.builder()
                .instructionFileConfig(InstructionFileConfig.builder()
                        .disableInstructionFile(false)
                        .instructionFileClient(S3Client.create())
                        .build())
                .kmsKeyId(KMS_KEY_ID)
                .build();

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3ClientDisabledInstructionFile);
        s3ClientDisabledInstructionFile.close();
        s3Client.close();
    }

    /**
     * A simple, reusable round-trip (encryption + decryption) using a given
     * S3Client. Useful for testing client configuration.
     *
     * @param v3Client the client under test
     */
    private void simpleV3RoundTrip(final S3Client v3Client, final String objectKey) {
        final String input = "SimpleTestOfV3EncryptionClient";

        v3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build(),
                RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }
}
