// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.CompletionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

/**
 * This class is an integration test for Unauthenticated Ranged Get for AES/CBC and AES/GCM modes
 */
public class S3EncryptionClientRangedGetCompatibilityTest {

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

    static Object[] keyMaterialProvider() {
        return new Object[] {
                AES_KEY,
                RSA_KEY_PAIR,
        };
    }

    private static S3EncryptionClient.Builder addKeyMaterialToClient(S3EncryptionClient.Builder builder, Object keyMaterial) {
        if (keyMaterial instanceof  SecretKey) {
            builder.aesKey((SecretKey) keyMaterial);
        } else if (keyMaterial instanceof KeyPair) {
            builder.rsaKeyPair((KeyPair) keyMaterial);
        }
        return builder;
    }

    private static S3AsyncEncryptionClient.Builder addKeyMaterialToClient(S3AsyncEncryptionClient.Builder builder, Object keyMaterial) {
        if (keyMaterial instanceof  SecretKey) {
            builder.aesKey((SecretKey) keyMaterial);
        } else if (keyMaterial instanceof KeyPair) {
            builder.rsaKeyPair((KeyPair) keyMaterial);
        }
        return builder;
    }

    @ParameterizedTest
    @MethodSource("keyMaterialProvider")
    public void AsyncAesGcmV3toV3RangedGet(Object keyMaterial) {
        final String objectKey = appendTestSuffix("async-aes-gcm-v3-to-v3-ranged-get");

        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";

        // Async Client
        S3AsyncEncryptionClient.Builder clientBuilder = S3AsyncEncryptionClient.builder()
                .enableLegacyUnauthenticatedModes(true);
        addKeyMaterialToClient(clientBuilder, keyMaterial);
        S3AsyncClient asyncClient = clientBuilder.build();

        asyncClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncRequestBody.fromString(input)).join();

        // Valid Range
        ResponseBytes<GetObjectResponse> objectResponse = asyncClient.getObject(builder -> builder
                .bucket(BUCKET)
                .range("bytes=10-20")
                .key(objectKey), AsyncResponseTransformer.toBytes()).join();
        String output = objectResponse.asUtf8String();
        assertEquals("klmnopqrst0", output);

        // Valid start index within input and end index out of range, returns object from start index to End of Stream
        objectResponse = asyncClient.getObject(builder -> builder
                .bucket(BUCKET)
                .range("bytes=190-300")
                .key(objectKey), AsyncResponseTransformer.toBytes()).join();
        output = objectResponse.asUtf8String();
        assertEquals("KLMNOPQRST", output);

        // Valid start index within input and without specifying end index of range, returns object from start index to End of Stream
        objectResponse = asyncClient.getObject(builder -> builder
                .bucket(BUCKET)
                .range("bytes=40-")
                .key(objectKey), AsyncResponseTransformer.toBytes()).join();
        output = objectResponse.asUtf8String();
        assertEquals(input.substring(40), output);

        // Invalid range with only specifying the end index, returns entire object
        objectResponse = asyncClient.getObject(builder -> builder
                .bucket(BUCKET)
                .range("bytes=-40")
                .key(objectKey), AsyncResponseTransformer.toBytes()).join();
        output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Invalid range start index range greater than ending index, returns entire object
        objectResponse = asyncClient.getObject(builder -> builder
                .bucket(BUCKET)
                .range("bytes=100-50")
                .key(objectKey), AsyncResponseTransformer.toBytes()).join();
        output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Invalid range format, returns entire object
        objectResponse = asyncClient.getObject(builder -> builder
                .bucket(BUCKET)
                .range("10-20")
                .key(objectKey), AsyncResponseTransformer.toBytes()).join();
        output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Invalid range starting index and ending index greater than object length but within Cipher Block size, returns empty object
        objectResponse = asyncClient.getObject(builder -> builder
                .bucket(BUCKET)
                .range("bytes=216-217")
                .key(objectKey), AsyncResponseTransformer.toBytes()).join();
        output = objectResponse.asUtf8String();
        assertEquals("", output);

        // Cleanup
        deleteObject(BUCKET, objectKey, asyncClient);
        asyncClient.close();
    }

    @ParameterizedTest
    @MethodSource("keyMaterialProvider")
    public void AsyncFailsOnRangeWhenLegacyModeDisabled(Object keyMaterial) {
        final String objectKey = appendTestSuffix("fails-when-on-range-when-legacy-disabled");
        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";

        // V3 Client
        S3AsyncEncryptionClient.Builder clientBuilder = S3AsyncEncryptionClient.builder();
        addKeyMaterialToClient(clientBuilder, keyMaterial);
        S3AsyncClient asyncClient = clientBuilder.build();

        asyncClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncRequestBody.fromString(input)).join();

        assertThrows(S3EncryptionClientException.class, () -> asyncClient.getObject(builder -> builder
                .bucket(BUCKET)
                .range("bytes=10-20")
                .key(objectKey), AsyncResponseTransformer.toBytes()).join());

        // Cleanup
        deleteObject(BUCKET, objectKey, asyncClient);
        asyncClient.close();
    }

    @Test
    public void AsyncAesCbcV1toV3RangedGet() {
        final String objectKey = appendTestSuffix("aes-cbc-v1-to-v3-ranged-get-async");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration();
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";

        v1Client.putObject(BUCKET, objectKey, input);

        // V3 Client
        S3AsyncClient v3Client = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Valid Range
        ResponseBytes<GetObjectResponse> objectResponse;

        objectResponse = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .range("bytes=10-20")
                .key(objectKey), AsyncResponseTransformer.toBytes()).join();
        String output;
        output = objectResponse.asUtf8String();
        assertEquals("klmnopqrst0", output);

        // Valid start index within input and end index out of range, returns object from start index to End of Stream
        objectResponse = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .range("bytes=190-300")
                .key(objectKey), AsyncResponseTransformer.toBytes()).join();
        output = objectResponse.asUtf8String();
        assertEquals("KLMNOPQRST", output);

        // Invalid range start index range greater than ending index, returns entire object
        objectResponse = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .range("bytes=100-50")
                .key(objectKey), AsyncResponseTransformer.toBytes()).join();
        output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Invalid range format, returns entire object
        objectResponse = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .range("10-20")
                .key(objectKey), AsyncResponseTransformer.toBytes()).join();
        output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Invalid range starting index and ending index greater than object length but within Cipher Block size, returns empty object
        objectResponse = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .range("bytes=216-217")
                .key(objectKey), AsyncResponseTransformer.toBytes()).join();
        output = objectResponse.asUtf8String();
        assertEquals("", output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }


    @ParameterizedTest
    @MethodSource("keyMaterialProvider")
    public void failsOnRangeWhenLegacyModeDisabled(Object keyMaterial) {
        final String objectKey = appendTestSuffix("fails-when-on-range-when-legacy-disabled");
        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Asserts
        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .range("bytes=10-20")));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @ParameterizedTest
    @MethodSource("keyMaterialProvider")
    public void AesGcmV3toV3RangedGet(Object keyMaterial) {
        final String objectKey = appendTestSuffix("aes-gcm-v3-to-v3-ranged-get");

        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";

        // V3 Client
        S3EncryptionClient.Builder clientBuilder = S3EncryptionClient.builder()
                .enableLegacyUnauthenticatedModes(true);
        addKeyMaterialToClient(clientBuilder, keyMaterial);
        S3Client v3Client = clientBuilder.build();

        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Valid Range
        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=10-20")
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals("klmnopqrst0", output);

        // Valid start index within input and end index out of range, returns object from start index to End of Stream
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=190-300")
                .key(objectKey));
        output = objectResponse.asUtf8String();
        assertEquals("KLMNOPQRST", output);

        // Valid start index within input and without specifying end index of range, returns object from start index to End of Stream
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=40-")
                .key(objectKey));
        output = objectResponse.asUtf8String();
        assertEquals(input.substring(40), output);

        // Invalid range with only specifying the end index, returns entire object
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=-40")
                .key(objectKey));
        output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Invalid range start index range greater than ending index, returns entire object
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=100-50")
                .key(objectKey));
        output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Invalid range format, returns entire object
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("10-20")
                .key(objectKey));
        output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Invalid range starting index and ending index greater than object length but within Cipher Block size, returns empty object
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=216-217")
                .key(objectKey));
        output = objectResponse.asUtf8String();
        assertEquals("", output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @ParameterizedTest
    @MethodSource("keyMaterialProvider")
    public void AesGcmV3toV3FailsRangeExceededObjectLength(Object keyMaterial) {
        final String objectKey = appendTestSuffix("aes-gcm-v3-to-v3-ranged-get-out-of-range");

        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";

        // V3 Client
        S3EncryptionClient.Builder clientBuilder = S3EncryptionClient.builder()
                .enableLegacyUnauthenticatedModes(true);
        addKeyMaterialToClient(clientBuilder, keyMaterial);
        S3Client v3Client = clientBuilder.build();

        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Invalid range exceed object length, Throws S3EncryptionClientException wrapped with S3Exception
        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=300-400")
                .key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @ParameterizedTest
    @MethodSource("keyMaterialProvider")
    public void AsyncAesGcmV3toV3FailsRangeExceededObjectLength(Object keyMaterial) {
        final String objectKey = appendTestSuffix("aes-gcm-v3-to-v3-ranged-get-out-of-range");

        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";

        // Async Client
        S3AsyncEncryptionClient.Builder clientBuilder = S3AsyncEncryptionClient.builder()
                .enableLegacyUnauthenticatedModes(true);
        addKeyMaterialToClient(clientBuilder, keyMaterial);
        S3AsyncClient asyncClient = clientBuilder.build();
        asyncClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), AsyncRequestBody.fromString(input)).join();
        try {
            // Invalid range exceed object length, Throws S3Exception nested inside CompletionException
            asyncClient.getObject(builder -> builder
                    .bucket(BUCKET)
                    .range("bytes=300-400")
                    .key(objectKey), AsyncResponseTransformer.toBytes()).join();
        } catch (CompletionException e) {
            assertEquals(S3Exception.class, e.getCause().getClass());
        }
        // Cleanup
        deleteObject(BUCKET, objectKey, asyncClient);
        asyncClient.close();
    }

    @Test
    public void AesCbcV1toV3RangedGet() {
        final String objectKey = appendTestSuffix("aes-cbc-v1-to-v3-ranged-get");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration();
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // This string is 200 characters/bytes long
        // Due to padding, its ciphertext will be 208 bytes
        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";

        v1Client.putObject(BUCKET, objectKey, input);

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Valid Range
        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=10-20")
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals("klmnopqrst0", output);

        // Valid start index within input and end index out of range, returns object from start index to End of Stream
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=190-300")
                .key(objectKey));
        output = objectResponse.asUtf8String();
        assertEquals("KLMNOPQRST", output);

        // Invalid range start index range greater than ending index, returns entire object
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=100-50")
                .key(objectKey));
        output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Valid start index within input and without specifying end index of range, returns object from start index to End of Stream
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=40-")
                .key(objectKey));
        output = objectResponse.asUtf8String();
        assertEquals(input.substring(40), output);

        // Invalid range with only specifying the end index, returns entire object
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=-40")
                .key(objectKey));
        output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Invalid range format, returns entire object
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("10-20")
                .key(objectKey));
        output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Invalid range starting index and ending index greater than object length
        // but within Cipher Block size, returns empty object
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=216-217")
                .key(objectKey));
        output = objectResponse.asUtf8String();
        assertEquals("", output);

        // Invalid range starting index and ending index greater than object length
        // but within Cipher Block size, returns empty object
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=216-218")
                .key(objectKey));
        output = objectResponse.asUtf8String();
        assertEquals("", output);


        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void AesCbcV1toV3FailsRangeExceededObjectLength() {
        final String objectKey = appendTestSuffix("aes-cbc-v1-to-v3-ranged-get-out-of-range");

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration();
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";

        v1Client.putObject(BUCKET, objectKey, input);

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Invalid range exceed object length, Throws S3EncryptionClientException wrapped with S3Exception
        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=300-400")
                .key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

}
