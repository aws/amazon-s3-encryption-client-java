// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoConfigurationV2;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.KMSEncryptionMaterials;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.NotFoundException;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.multipart.MultipartConfiguration;
import software.amazon.encryption.s3.internal.InstructionFileConfig;
import software.amazon.encryption.s3.materials.KmsKeyring;
import software.amazon.encryption.s3.utils.BoundedInputStream;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;
import software.amazon.encryption.s3.utils.TinyBufferAsyncRequestBody;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.ALTERNATE_KMS_KEY;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_REGION;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.S3_REGION;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class S3AsyncEncryptionClientTest {

    private static SecretKey AES_KEY;
    private static Provider PROVIDER;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();
        Security.addProvider(new BouncyCastleProvider());
        PROVIDER = Security.getProvider("BC");
    }

    //@Test
    public void asyncCustomConfiguration() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-custom-credentials-async");

        // use the default creds, but through an explicit credentials provider
        AwsCredentialsProvider creds = DefaultCredentialsProvider.create();

        S3AsyncClient wrappedAsyncClient = S3AsyncClient
                .builder()
                .credentialsProvider(creds)
                .region(Region.of(S3_REGION.toString()))
                .build();
        KmsClient kmsClient = KmsClient
                .builder()
                .credentialsProvider(creds)
                .region(Region.of(KMS_REGION.toString()))
                .build();

        KmsKeyring keyring = KmsKeyring
                .builder()
                .kmsClient(kmsClient)
                .wrappingKeyId(KMS_KEY_ID)
                .build();
        S3AsyncClient s3Client = S3AsyncEncryptionClient.builder()
                .wrappedClient(wrappedAsyncClient)
                .keyring(keyring)
                .build();

        final String input = "SimpleTestOfV3EncryptionClientAsync";

        s3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build(),
                AsyncRequestBody.fromString(input)).join();

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncResponseTransformer.toBytes()).join();
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        wrappedAsyncClient.close();
        s3Client.close();
    }

    //@Test
    public void asyncTopLevelConfigurationAllOptions() {
        final String objectKey = appendTestSuffix("async-top-level-all-options");
        AwsCredentialsProvider creds = DefaultCredentialsProvider.create();
        // use all top-level options;
        // there isn't a good way to validate every option.
        S3AsyncClient s3Client = S3AsyncEncryptionClient.builder()
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
                // .multipartEnabled(false)
                // .multipartConfiguration(MultipartConfiguration.builder().build()) // null is ambiguous
                .disableS3ExpressSessionAuth(null)
                .crossRegionAccessEnabled(null)
                .instructionFileConfig(InstructionFileConfig.builder().instructionFileClient(S3Client.create()).build())
                .build();
        final String input = "SimpleTestOfV3EncryptionClientAsync";

        s3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build(),
                AsyncRequestBody.fromString(input)).join();

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncResponseTransformer.toBytes()).join();
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    //@Test
    public void asyncTopLevelConfiguration() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-top-level-credentials-async");

        // use the default creds, but through an explicit credentials provider
        AwsCredentialsProvider creds = DefaultCredentialsProvider.create();

        S3AsyncClient s3Client = S3AsyncEncryptionClient.builder()
                .credentialsProvider(creds)
                .region(Region.of(KMS_REGION.toString()))
                .kmsKeyId(KMS_KEY_ID)
                .build();

        final String input = "SimpleTestOfV3EncryptionClientAsync";

        s3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build(),
                AsyncRequestBody.fromString(input)).join();

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncResponseTransformer.toBytes()).join();
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    //@Test
    public void s3AsyncEncryptionClientTopLevelAlternateCredentials() {
        final String objectKey = appendTestSuffix("wrapped-s3-async-client-with-top-level-alternate-credentials");
        final String input = "S3EncryptionClientTopLevelAlternateCredsTest";

        // use alternate creds
        AwsCredentialsProvider creds = new S3EncryptionClientTestResources.AlternateRoleCredentialsProvider();

        S3AsyncClient s3Client = S3AsyncEncryptionClient.builder()
                .credentialsProvider(creds)
                .region(Region.of(KMS_REGION.toString()))
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // using the original key fails
        try {
            s3Client.putObject(builder -> builder
                            .bucket(BUCKET)
                            .key(objectKey)
                            .build(),
                    AsyncRequestBody.fromString(input)).join();
            fail("expected exception");
        } catch (KmsException exception) {
            // expected
            assertTrue(exception.getMessage().contains("is not authorized to perform"));
        } finally {
            s3Client.close();
        }

        // using the alternate key succeeds
        S3AsyncClient s3ClientAltCreds = S3AsyncEncryptionClient.builder()
                .credentialsProvider(creds)
                .region(Region.of(KMS_REGION.toString()))
                .kmsKeyId(ALTERNATE_KMS_KEY)
                .build();

        s3ClientAltCreds.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build(),
                AsyncRequestBody.fromString(input)).join();

        ResponseBytes<GetObjectResponse> objectResponse = s3ClientAltCreds.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncResponseTransformer.toBytes()).join();
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3ClientAltCreds);
        s3ClientAltCreds.close();
    }

    //@Test
    public void s3AsyncEncryptionClientMixedCredentials() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-mixed-credentials");
        final String input = "S3EncryptionClientTopLevelAlternateCredsTest";

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

        S3AsyncClient s3Client = S3AsyncEncryptionClient.builder()
                .credentialsProvider(creds)
                .region(Region.of(KMS_REGION.toString()))
                .keyring(kmsKeyring)
                .build();

        s3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build(),
                AsyncRequestBody.fromString(input)).join();

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncResponseTransformer.toBytes()).join();
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
        kmsClient.close();
    }

    //@Test
    public void asyncTopLevelConfigurationWrongRegion() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-wrong-region-credentials-async");

        AwsCredentialsProvider creds = DefaultCredentialsProvider.create();

        S3AsyncClient s3Client = S3AsyncEncryptionClient.builder()
                .credentialsProvider(creds)
                .region(Region.of("eu-west-1"))
                .kmsKeyId(KMS_KEY_ID)
                .build();

        final String input = "SimpleTestOfV3EncryptionClientAsync";

        try {
            s3Client.putObject(builder -> builder
                            .bucket(BUCKET)
                            .key(objectKey)
                            .build(),
                    AsyncRequestBody.fromString(input)).join();
            fail("expected exception");
        } catch (NotFoundException e) {
            assertTrue(e.getMessage().contains("Invalid arn"));
        } finally {
            s3Client.close();
        }
    }

    //@Test
    public void asyncTopLevelConfigurationNullCreds() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-null-credentials-async");

        AwsCredentialsProvider creds = new S3EncryptionClientTestResources.NullCredentialsProvider();

        S3AsyncClient s3Client = S3AsyncEncryptionClient.builder()
                .credentialsProvider(creds)
                .region(Region.of(KMS_REGION.toString()))
                .kmsKeyId(KMS_KEY_ID)
                .build();

        final String input = "SimpleTestOfV3EncryptionClientAsync";

        try {
            s3Client.putObject(builder -> builder
                            .bucket(BUCKET)
                            .key(objectKey)
                            .build(),
                    AsyncRequestBody.fromString(input)).join();
            fail("expected exception");
        } catch (NullPointerException npe) {
            assertTrue(npe.getMessage().contains("Access key ID cannot be blank"));
        } finally {
            s3Client.close();
        }
    }

    //@Test
    public void putAsyncGetDefault() {
        final String objectKey = appendTestSuffix("put-async-get-default");

        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        final String input = "PutAsyncGetDefault";

        CompletableFuture<PutObjectResponse> futurePut = v3AsyncClient.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncRequestBody.fromString(input));
        // Block on completion of the futurePut
        futurePut.join();

        ResponseBytes<GetObjectResponse> getResponse = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), ResponseTransformer.toBytes());
        assertEquals(input, getResponse.asUtf8String());

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
        v3AsyncClient.close();
    }

    //@Test
    public void putDefaultGetAsync() {
        final String objectKey = appendTestSuffix("put-default-get-async");

        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        final String input = "PutDefaultGetAsync";

        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        CompletableFuture<ResponseBytes<GetObjectResponse>> futureGet = v3AsyncClient.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncResponseTransformer.toBytes());
        // Just wait for the future to complete
        ResponseBytes<GetObjectResponse> getResponse = futureGet.join();
        assertEquals(input, getResponse.asUtf8String());

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
        v3AsyncClient.close();
    }

    //@Test
    public void putAsyncGetAsync() {
        final String objectKey = appendTestSuffix("put-async-get-async");

        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        final String input = "PutAsyncGetAsync";

        CompletableFuture<PutObjectResponse> futurePut = v3AsyncClient.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncRequestBody.fromString(input));
        // Block on completion of the futurePut
        futurePut.join();

        CompletableFuture<ResponseBytes<GetObjectResponse>> futureGet = v3AsyncClient.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncResponseTransformer.toBytes());
        // Just wait for the future to complete
        ResponseBytes<GetObjectResponse> getResponse = futureGet.join();
        assertEquals(input, getResponse.asUtf8String());

        // Cleanup
        deleteObject(BUCKET, objectKey, v3AsyncClient);
        v3AsyncClient.close();
    }

    //@Test
    public void aesCbcV1toV3Async() {
        final String objectKey = appendTestSuffix("aes-cbc-v1-to-v3-async");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration();
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST";

        v1Client.putObject(BUCKET, objectKey, input);

        // V3 Client
        S3AsyncClient v3Client = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        CompletableFuture<ResponseBytes<GetObjectResponse>> futureResponse = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), AsyncResponseTransformer.toBytes());
        ResponseBytes<GetObjectResponse> response = futureResponse.join();
        String output = response.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void failAesCbcV1toV3AsyncWhenDisabled() {
        final String objectKey = appendTestSuffix("fail-aes-cbc-v1-to-v3-async-when-disabled");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration();
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST";

        v1Client.putObject(BUCKET, objectKey, input);

        // V3 Client
        S3AsyncClient v3Client = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .build();
        try {
            CompletableFuture<ResponseBytes<GetObjectResponse>> futureResponse = v3Client.getObject(builder -> builder
                    .bucket(BUCKET)
                    .key(objectKey), AsyncResponseTransformer.toBytes());
            futureResponse.join();
        } catch (CompletionException e) {
            assertEquals(S3EncryptionClientException.class, e.getCause().getClass());
        }

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void AsyncAesGcmV2toV3WithInstructionFile() {
        final String objectKey = appendTestSuffix("async-aes-gcm-v2-to-v3-with-instruction-file");

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

        // V3 Async Client
        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .instructionFileConfig(InstructionFileConfig.builder().instructionFileClient(S3Client.create()).build())
                .build();

        // Asserts
        final String input = "AesGcmV2toV3";
        v2Client.putObject(BUCKET, objectKey, input);

        CompletableFuture<ResponseBytes<GetObjectResponse>> futureGet = v3AsyncClient.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncResponseTransformer.toBytes());
        String outputAsync = futureGet.join().asUtf8String();
        assertEquals(input, outputAsync);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3AsyncClient);
        v3AsyncClient.close();
    }

    //@Test
    public void deleteObjectWithInstructionFileSuccessAsync() {
        final String objectKey = appendTestSuffix("async-delete-object-with-instruction-file");

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
        S3AsyncClient v3Client = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        final String input = "DeleteObjectWithInstructionFileSuccess";
        v2Client.putObject(BUCKET, objectKey, input);

        // Delete Object
        CompletableFuture<DeleteObjectResponse> response = v3Client.deleteObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        // Ensure completion
        response.join();

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

    //@Test
    public void deleteObjectsWithInstructionFilesSuccessAsync() {
        final String[] objectKeys = {appendTestSuffix("async-delete-object-with-instruction-file-1"),
                appendTestSuffix("async-delete-object-with-instruction-file-2"),
                appendTestSuffix("async-delete-object-with-instruction-file-3")};

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
        S3AsyncClient v3Client = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        final String input = "DeleteObjectsWithInstructionFileSuccess";
        List<ObjectIdentifier> objects = new ArrayList<>();
        for (String objectKey : objectKeys) {
            v2Client.putObject(BUCKET, objectKey, input);
            objects.add(ObjectIdentifier.builder().key(objectKey).build());
        }

        // Delete Objects from S3 Buckets
        CompletableFuture<DeleteObjectsResponse> response = v3Client.deleteObjects(builder -> builder
                .bucket(BUCKET)
                .delete(builder1 -> builder1.objects(objects)));
        // Block on completion
        response.join();

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

    //@Test
    public void deleteObjectWithWrongObjectKeySuccessAsync() {
        // V3 Client
        S3AsyncClient v3Client = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        assertDoesNotThrow(() -> v3Client.deleteObject(builder -> builder.bucket(BUCKET).key("InvalidKey")));

        // Cleanup
        v3Client.close();
    }

    //@Test
    public void copyObjectTransparentlyAsync() {
        final String objectKey = appendTestSuffix("copy-object-from-here-async");
        final String newObjectKey = appendTestSuffix("copy-object-to-here-async");

        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        final String input = "CopyObjectAsync";

        CompletableFuture<PutObjectResponse> futurePut = v3AsyncClient.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncRequestBody.fromString(input));
        // Block on completion of the futurePut
        futurePut.join();

        CompletableFuture<CopyObjectResponse> futureCopy = v3AsyncClient.copyObject(builder -> builder
                .sourceBucket(BUCKET)
                .destinationBucket(BUCKET)
                .sourceKey(objectKey)
                .destinationKey(newObjectKey)
                .build());
        // Block on copy future
        futureCopy.join();

        // Decrypt new object
        CompletableFuture<ResponseBytes<GetObjectResponse>> futureGet = v3AsyncClient.getObject(builder -> builder
                .bucket(BUCKET)
                .key(newObjectKey)
                .build(), AsyncResponseTransformer.toBytes());
        ResponseBytes<GetObjectResponse> getResponse = futureGet.join();
        assertEquals(input, getResponse.asUtf8String());

        // Cleanup
        deleteObject(BUCKET, objectKey, v3AsyncClient);
        deleteObject(BUCKET, newObjectKey, v3AsyncClient);
        v3AsyncClient.close();
    }

    /**
     * Test which artificially limits the size of buffers using {@link TinyBufferAsyncRequestBody}.
     * This tests edge cases where network conditions result in buffers with length shorter than
     * the cipher's block size.
     * @throws IOException
     */
    //@Test
    public void tinyBufferTest() throws IOException {
        // BouncyCastle actually returns null buffers, unlike ACCP and SunJCE, which return empty buffers
        Security.addProvider(new BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");
        final String objectKey = appendTestSuffix("tiny-buffer-async");

        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .cryptoProvider(provider)
                .build();

        // need enough data to split up
        final long inputLength = 1024;
        final InputStream input = new BoundedInputStream(inputLength);
        final InputStream inputClean = new BoundedInputStream(inputLength);

        final ExecutorService exec = Executors.newSingleThreadExecutor();

        // Use this request body to limit the buffer size
        TinyBufferAsyncRequestBody tinyBufferAsyncRequestBody = new TinyBufferAsyncRequestBody(AsyncRequestBody.fromInputStream(input, inputLength, exec));
        CompletableFuture<PutObjectResponse> futurePut = v3AsyncClient.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), tinyBufferAsyncRequestBody);
        futurePut.join();

        CompletableFuture<ResponseBytes<GetObjectResponse>> futureGet = v3AsyncClient.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncResponseTransformer.toBytes());
        ResponseBytes<GetObjectResponse> getResponse = futureGet.join();
        assertTrue(IOUtils.contentEquals(inputClean, getResponse.asInputStream()));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3AsyncClient);
        v3AsyncClient.close();
        exec.shutdown();
    }

    //@Test
    public void testAsyncInstructionFileConfig() {
        final String objectKey = appendTestSuffix("async-instruction-file-config");
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

        S3AsyncClient s3ClientDisabledInstructionFile = S3AsyncEncryptionClient.builder()
                .instructionFileConfig(InstructionFileConfig.builder()
                        .disableInstructionFile(true)
                        .build())
                .kmsKeyId(KMS_KEY_ID)
                .build();

        try {
            s3ClientDisabledInstructionFile.getObject(builder -> builder
                    .bucket(BUCKET)
                    .key(objectKey)
                    .build(), AsyncResponseTransformer.toBytes()).join();
            fail("expected exception");
        } catch (Exception exception) {
            assertEquals(exception.getCause().getClass(), S3EncryptionClientException.class);
            assertTrue(exception.getMessage().contains("Exception encountered while fetching Instruction File."));
        }

        S3Client s3Client = S3EncryptionClient.builder()
                .instructionFileConfig(InstructionFileConfig.builder()
                        .instructionFileClient(S3Client.create())
                        .disableInstructionFile(false)
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

    //@Test
    public void wrappedClientMultipartUploadThrowsException() throws IOException {
        final String objectKey = appendTestSuffix("multipart-put-object-async-wrapped-client");

        final long fileSizeLimit = 1024 * 1024 * 100;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
        final InputStream objectStreamForResult = new BoundedInputStream(fileSizeLimit);

        // using top-level configuration throws an exception
        try {
            S3AsyncEncryptionClient.builder()
                    .kmsKeyId(KMS_KEY_ID)
                    .enableMultipartPutObject(true)
                    .multipartEnabled(true)
                    .enableDelayedAuthenticationMode(true)
                    .enableLegacyUnauthenticatedModes(true)
                    .cryptoProvider(PROVIDER)
                    .build();
            fail("expected exception");
        } catch (UnsupportedOperationException exception) {
            assertTrue(exception.getMessage().contains("S3 Encryption Client"));
        }

        // passing a wrapped client will throw an exception,
        // but not until GetObject is called
        S3AsyncClient wrappedClient = S3AsyncClient.builder()
                .multipartEnabled(true)
                .build();
        S3AsyncClient v3Client = S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableMultipartPutObject(true)
                .wrappedClient(wrappedClient)
                .enableDelayedAuthenticationMode(true)
                .enableLegacyUnauthenticatedModes(true)
                .cryptoProvider(PROVIDER)
                .build();

        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        ExecutorService singleThreadExecutor = Executors.newSingleThreadExecutor();

        CompletableFuture<PutObjectResponse> futurePut = v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
                .key(objectKey), AsyncRequestBody.fromInputStream(inputStream, fileSizeLimit, singleThreadExecutor));
        futurePut.join();
        singleThreadExecutor.shutdown();

        // using the same MPU client should fail
        try {
            v3Client.getObject(builder -> builder
                    .bucket(BUCKET)
                    .overrideConfiguration(S3EncryptionClient.withAdditionalConfiguration(encryptionContext))
                    .key(objectKey), AsyncResponseTransformer.toBlockingInputStream()).join();
            fail("expected exception");
        } catch (CompletionException exception) {
            assertEquals(S3EncryptionClientException.class, exception.getCause().getClass());
        }

        // using a client without MPU should pass
        S3AsyncClient v3ClientGet = S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(PROVIDER)
                .build();

        CompletableFuture<ResponseInputStream<GetObjectResponse>> getFuture = v3ClientGet.getObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(S3EncryptionClient.withAdditionalConfiguration(encryptionContext))
                .key(objectKey), AsyncResponseTransformer.toBlockingInputStream());
        ResponseInputStream<GetObjectResponse> output = getFuture.join();

        assertTrue(IOUtils.contentEquals(objectStreamForResult, output));

        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void S3AsyncClientBuilderForbidsMultipartEnabled() throws IOException {
        assertThrows(
            UnsupportedOperationException.class,
            () -> S3AsyncEncryptionClient.builder().multipartEnabled(Boolean.TRUE));
    }

    //@Test
    public void S3AsyncClientBuilderForbidsMultipartConfiguration() throws IOException {
        assertThrows(
            UnsupportedOperationException.class,
            () -> S3AsyncEncryptionClient.builder().multipartConfiguration(MultipartConfiguration.builder().build()));
    }
}
