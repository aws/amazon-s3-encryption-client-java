// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.utils.BoundedStreamBufferer;
import software.amazon.encryption.s3.utils.BoundedInputStream;
import software.amazon.encryption.s3.utils.MarkResetBoundedZerosInputStream;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import javax.crypto.AEADBadTagException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

/**
 * Test the streaming functionality using various stream implementations.
 */
public class S3EncryptionClientStreamTest {

    private static final String BUCKET = S3EncryptionClientTestResources.BUCKET;
    private static final int DEFAULT_TEST_STREAM_LENGTH = (int) (Math.random() * 10000);

    private static SecretKey AES_KEY;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();
    }

    @Test
    public void markResetInputStreamV3Encrypt() throws IOException {
        final String objectKey = appendTestSuffix("markResetInputStreamV3Encrypt");
        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        final int inputLength = DEFAULT_TEST_STREAM_LENGTH;
        final InputStream inputStream = new MarkResetBoundedZerosInputStream(inputLength);
        inputStream.mark(inputLength);
        final String inputStreamAsUtf8String = IoUtils.toUtf8String(inputStream);
        inputStream.reset();

        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromInputStream(inputStream, inputLength));
        inputStream.close();

        final String actualObject = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build()).asUtf8String();

        assertEquals(inputStreamAsUtf8String, actualObject);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void ordinaryInputStreamV3Encrypt() throws IOException {
        final String objectKey = appendTestSuffix("ordinaryInputStreamV3Encrypt");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        final int inputLength = DEFAULT_TEST_STREAM_LENGTH;
        // Create a second stream of zeros because reset is not supported
        // and reading into the byte string will consume the stream.
        final InputStream inputStream = new BoundedInputStream(inputLength);
        final InputStream inputStreamForString = new BoundedInputStream(inputLength);
        final String inputStreamAsUtf8String = IoUtils.toUtf8String(inputStreamForString);

        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromInputStream(inputStream, inputLength));
        inputStream.close();

        final String actualObject = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build()).asUtf8String();

        assertEquals(inputStreamAsUtf8String, actualObject);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void ordinaryInputStreamV3Decrypt() throws IOException {
        final String objectKey = appendTestSuffix("ordinaryInputStreamV3Decrypt");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        final int inputLength = DEFAULT_TEST_STREAM_LENGTH;
        // Create a second stream of zeros because reset is not supported
        // and reading into the byte string will consume the stream.
        final InputStream inputStream = new BoundedInputStream(inputLength);
        final InputStream inputStreamForString = new BoundedInputStream(inputLength);
        final String inputStreamAsUtf8String = IoUtils.toUtf8String(inputStreamForString);

        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromInputStream(inputStream, inputLength));
        inputStream.close();

        final ResponseInputStream<GetObjectResponse> responseInputStream = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());
        final String actualObject = new String(BoundedStreamBufferer.toByteArray(responseInputStream, inputLength / 8),
                StandardCharsets.UTF_8);

        assertEquals(inputStreamAsUtf8String, actualObject);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void ordinaryInputStreamV3DecryptCbc() throws IOException {
        final String objectKey = appendTestSuffix("markResetInputStreamV3DecryptCbc");

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

        final int inputLength = DEFAULT_TEST_STREAM_LENGTH;
        final InputStream inputStreamForString = new BoundedInputStream(inputLength);
        final String inputStreamAsUtf8String = IoUtils.toUtf8String(inputStreamForString);

        v1Client.putObject(BUCKET, objectKey, inputStreamAsUtf8String);

        final ResponseInputStream<GetObjectResponse> responseInputStream = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());
        final String actualObject = new String(BoundedStreamBufferer.toByteArray(responseInputStream, inputLength / 8),
                StandardCharsets.UTF_8);

        assertEquals(inputStreamAsUtf8String, actualObject);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void invalidBufferSize() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .setBufferSize(15L)
                .build());
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .setBufferSize(68719476705L)
                .build());

        assertThrows(S3EncryptionClientException.class, () -> S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .setBufferSize(15L)
                .build());
        assertThrows(S3EncryptionClientException.class, () -> S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .setBufferSize(68719476705L)
                .build());
    }

    @Test
    public void failsWhenBothBufferSizeAndDelayedAuthModeEnabled() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .setBufferSize(16)
                .enableDelayedAuthenticationMode(true)
                .build());

        assertThrows(S3EncryptionClientException.class, () -> S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .setBufferSize(16)
                .enableDelayedAuthenticationMode(true)
                .build());
    }

    @Test
    public void customSetBufferSizeWithLargeObject() throws IOException {
        final String objectKey = appendTestSuffix("large-object-test-custom-buffer-size");

        Security.addProvider(new BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");

        // V3 Client with custom max buffer size 32 MiB.
        S3Client v3ClientWithBuffer32MiB = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .cryptoProvider(provider)
                .setBufferSize(32 * 1024 * 1024)
                .build();

        // V3 Client with default buffer size (i.e. 64MiB)
        // When enableDelayedAuthenticationMode is set to true, delayed authentication mode always takes priority over buffered mode.
        S3Client v3ClientWithDelayedAuth = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .cryptoProvider(provider)
                .enableDelayedAuthenticationMode(true)
                .build();

        // Tight bound on the custom buffer size limit of 32MiB
        final long fileSizeExceedingDefaultLimit = 1024 * 1024 * 32 + 1;
        final InputStream largeObjectStream = new BoundedInputStream(fileSizeExceedingDefaultLimit);
        v3ClientWithBuffer32MiB.putObject(PutObjectRequest.builder()
                                   .bucket(BUCKET)
                                   .key(objectKey)
                                   .build(), RequestBody.fromInputStream(largeObjectStream, fileSizeExceedingDefaultLimit));

        largeObjectStream.close();

        // Object is larger than Buffer, so getObject fails
        assertThrows(S3EncryptionClientException.class, () -> v3ClientWithBuffer32MiB.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));

        // You have to either enable the delayed auth mode or increase max buffer size (but in allowed bounds)
        ResponseInputStream<GetObjectResponse> response = v3ClientWithDelayedAuth.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));


        assertTrue(IOUtils.contentEquals(new BoundedInputStream(fileSizeExceedingDefaultLimit), response));
        response.close();

        // Cleanup
        deleteObject(BUCKET, objectKey, v3ClientWithBuffer32MiB);
        v3ClientWithBuffer32MiB.close();
        v3ClientWithDelayedAuth.close();
    }

    @Test
    public void customSetBufferSizeWithLargeObjectAsyncClient() throws IOException {
        final String objectKey = appendTestSuffix("large-object-test-custom-buffer-size-async");

        Security.addProvider(new BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");

        // V3 Client with custom max buffer size 32 MiB.
        S3AsyncClient v3ClientWithBuffer32MiB = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .cryptoProvider(provider)
                .setBufferSize(32 * 1024 * 1024)
                .build();

        // V3 Client with default buffer size (i.e. 64MiB)
        // When enableDelayedAuthenticationMode is set to true, delayed authentication mode always takes priority over buffered mode.
        S3AsyncClient v3ClientWithDelayedAuth = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .cryptoProvider(provider)
                .enableDelayedAuthenticationMode(true)
                .build();

        // Tight bound on the custom buffer size limit of 32MiB
        final long fileSizeExceedingDefaultLimit = 1024 * 1024 * 32 + 1;
        final InputStream largeObjectStream = new BoundedInputStream(fileSizeExceedingDefaultLimit);
        ExecutorService singleThreadExecutor = Executors.newSingleThreadExecutor();
        CompletableFuture<PutObjectResponse> futurePut = v3ClientWithBuffer32MiB.putObject(PutObjectRequest.builder()
                                                                                           .bucket(BUCKET)
                                                                                           .key(objectKey)
                                                                                           .build(), AsyncRequestBody.fromInputStream(largeObjectStream, fileSizeExceedingDefaultLimit, singleThreadExecutor));

        futurePut.join();
        largeObjectStream.close();
        singleThreadExecutor.shutdown();

        try {
            // Object is larger than Buffer, so getObject fails
            CompletableFuture<ResponseInputStream<GetObjectResponse>> futureResponse = v3ClientWithBuffer32MiB.getObject(builder -> builder
                    .bucket(BUCKET)
                    .key(objectKey), AsyncResponseTransformer.toBlockingInputStream());
            futureResponse.join();
        } catch (CompletionException e) {
            assertEquals(S3EncryptionClientException.class, e.getCause().getClass());
        }

        // You have to either enable the delayed auth mode or increase max buffer size (but in allowed bounds)
        CompletableFuture<ResponseInputStream<GetObjectResponse>> futureGet = v3ClientWithDelayedAuth.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), AsyncResponseTransformer.toBlockingInputStream());
        ResponseInputStream<GetObjectResponse> output = futureGet.join();

        assertTrue(IOUtils.contentEquals(new BoundedInputStream(fileSizeExceedingDefaultLimit), output));
        output.close();

        // Cleanup
        deleteObject(BUCKET, objectKey, v3ClientWithBuffer32MiB);
        v3ClientWithBuffer32MiB.close();
        v3ClientWithDelayedAuth.close();
    }

    @Test
    public void delayedAuthModeWithLargeObject() throws IOException {
        final String objectKey = appendTestSuffix("large-object-test");

        Security.addProvider(new BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .cryptoProvider(provider)
                .build();

        // Tight bound on the default limit of 64MiB
        final long fileSizeExceedingDefaultLimit = 1024 * 1024 * 64 + 1;
        final InputStream largeObjectStream = new BoundedInputStream(fileSizeExceedingDefaultLimit);
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromInputStream(largeObjectStream, fileSizeExceedingDefaultLimit));

        largeObjectStream.close();

        // Delayed Authentication is not enabled, so getObject fails
        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));
                
        S3Client v3ClientWithDelayedAuth = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableDelayedAuthenticationMode(true)
                .build();

        // Once enabled, the getObject request passes
        ResponseInputStream<GetObjectResponse> response = v3ClientWithDelayedAuth.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));


        assertTrue(IOUtils.contentEquals(new BoundedInputStream(fileSizeExceedingDefaultLimit), response));
        response.close();

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void delayedAuthModeWithLargerThanMaxObjectFails() throws IOException {
        final String objectKey = appendTestSuffix("larger-than-max-object-delayed-auth-mode");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableDelayedAuthenticationMode(true)
                .build();

        final long fileSizeExceedingGCMLimit = (1L << 39) - 256 / 8;
        final InputStream largeObjectStream = new BoundedInputStream(fileSizeExceedingGCMLimit);
        assertThrows(S3EncryptionClientException.class, () -> v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromInputStream(largeObjectStream, fileSizeExceedingGCMLimit)));

        largeObjectStream.close();

        // Cleanup
        v3Client.close();
    }

    @Test
    public void AesGcmV3toV3StreamWithTamperedTag() {
        final String objectKey = appendTestSuffix("aes-gcm-v3-to-v3-stream-tamper-tag");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // 640 bytes of gibberish - enough to cover multiple blocks
        final String input = "1esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "2esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "3esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "4esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "5esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "6esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "7esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "8esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "9esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "10sAAAYoAesAAAEndOfChunkAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo";
        final int inputLength = input.length();
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Use an unencrypted (plaintext) client to interact with the encrypted object
        final S3Client plaintextS3Client = S3Client.builder().build();
        ResponseBytes<GetObjectResponse> objectResponse = plaintextS3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        final byte[] encryptedBytes = objectResponse.asByteArray();
        final int tagLength = 16;
        final byte[] tamperedBytes = new byte[inputLength + tagLength];
        // Copy the enciphered bytes
        System.arraycopy(encryptedBytes, 0, tamperedBytes, 0, inputLength);
        final byte[] tamperedTag = new byte[tagLength];
        // Increment the first byte of the tag
        tamperedTag[0] = (byte) (encryptedBytes[inputLength + 1] + 1);
        // Copy the rest of the tag as-is
        System.arraycopy(encryptedBytes, inputLength + 1, tamperedTag, 1, tagLength - 1);
        // Append the tampered tag
        System.arraycopy(tamperedTag, 0, tamperedBytes, inputLength, tagLength);

        // Sanity check that the objects differ
        assertNotEquals(encryptedBytes, tamperedBytes);

        // Replace the encrypted object with the tampered object
        PutObjectRequest tamperedPut = PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .metadata(objectResponse.response().metadata()) // Preserve metadata from encrypted object
                .build();
        plaintextS3Client.putObject(tamperedPut, RequestBody.fromBytes(tamperedBytes));

        // Get (and decrypt) the (modified) object from S3
        ResponseInputStream<GetObjectResponse> dataStream = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));

        final int chunkSize = 300;
        final byte[] chunk1 = new byte[chunkSize];

        // Stream decryption will throw an exception on the first byte read
        try {
            dataStream.read(chunk1, 0, chunkSize);
        } catch (RuntimeException outerEx) {
            assertTrue(outerEx.getCause() instanceof AEADBadTagException);
        } catch (IOException unexpected) {
            // Not expected, but fail the test anyway
            fail(unexpected);
        }

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }
}
