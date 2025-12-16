// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class S3EncryptionClientRsaKeyPairTest {
    private static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");

    private static KeyPair RSA_KEY_PAIR;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        RSA_KEY_PAIR = keyPairGen.generateKeyPair();
    }

    @Test
    public void RsaPublicAndPrivateKeys() {
        final String objectKey = appendTestSuffix("rsa-public-and-private");

        // V3 Client
        S3Client s3Client = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .rsaKeyPair(RSA_KEY_PAIR)
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
    public void RsaPrivateKeyCanOnlyDecrypt() {
        final String objectKey = appendTestSuffix("rsa-private-key-only");
        S3Client s3Client = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        S3Client s3ClientReadOnly = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .rsaKeyPair(new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), null))
                .build();

        final String input = "RsaOaepV3toV3";
        s3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = s3ClientReadOnly.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        assertThrows(S3EncryptionClientException.class, () -> s3ClientReadOnly.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(input)
                .build(), RequestBody.fromString(input)));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void RsaPublicKeyCanOnlyEncrypt() {
        final String objectKey = appendTestSuffix("rsa-public-key-only");
        S3Client s3Client = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .rsaKeyPair(new PartialRsaKeyPair(null, RSA_KEY_PAIR.getPublic()))
                .build();

        s3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(objectKey));

        assertThrows(S3EncryptionClientException.class, () -> s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }


}
