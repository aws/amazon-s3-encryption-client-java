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
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CopyObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.encryption.s3.utils.BoundedInputStream;
import software.amazon.encryption.s3.utils.TinyBufferAsyncRequestBody;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class S3AsyncEncryptionClientTest {

    private static SecretKey AES_KEY;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();
    }

    @Test
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

    @Test
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

    @Test
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

    @Test
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

    @Test
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

    @Test
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

    @Test
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

    @Test
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

    @Test
    public void deleteObjectWithWrongObjectKeySuccessAsync() {
        // V3 Client
        S3AsyncClient v3Client = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        assertDoesNotThrow(() -> v3Client.deleteObject(builder -> builder.bucket(BUCKET).key("InvalidKey")));

        // Cleanup
        v3Client.close();
    }

    @Test
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
    @Test
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

}
