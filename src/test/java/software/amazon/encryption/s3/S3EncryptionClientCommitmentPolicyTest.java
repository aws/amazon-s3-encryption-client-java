// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.ContentMetadataDecodingStrategy;
import software.amazon.encryption.s3.internal.MetadataKeyConstants;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class S3EncryptionClientCommitmentPolicyTest {

    private static SecretKey AES_KEY;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();
    }

    @Test
    public void testCommitmentPolicyAndEncryptionAlgorithm() {
        //= specification/s3-encryption/client.md#encryption-algorithm
        //= type=test
        //# The S3EC MUST support configuration of the encryption algorithm (or algorithm suite) during its initialization.
        //= specification/s3-encryption/client.md#encryption-algorithm
        //= type=test
        //# The S3EC MUST validate that the configured encryption algorithm is not legacy.
        //= specification/s3-encryption/client.md#key-commitment
        //= type=test
        //# The S3EC MUST support configuration of the [Key Commitment policy](./key-commitment.md) during its initialization.
        //= specification/s3-encryption/client.md#key-commitment
        //= type=test
        //# The S3EC MUST validate the configured Encryption Algorithm against the provided key commitment policy.
        S3EncryptionClient s3EncryptionClient = assertDoesNotThrow(() -> S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build());
        s3EncryptionClient.close();

        //= specification/s3-encryption/client.md#key-commitment
        //= type=test
        //# The S3EC MUST support configuration of the [Key Commitment policy](./key-commitment.md) during its initialization.
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build());
        assertTrue(exception.getMessage().contains("The commitment policy requires encryption with a committing algorithm suite, but the specified encryption algorithm does not support key commitment."));
        //= specification/s3-encryption/client.md#encryption-algorithm
        //= type=test
        //# The S3EC MUST support configuration of the encryption algorithm (or algorithm suite) during its initialization.
        S3EncryptionClientException exception1 = assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .build());
        assertTrue(exception1.getMessage().contains("The commitment policy forbids encryption with committing algorithm suites, but the specified encryption algorithm supports key commitment."));

        //= specification/s3-encryption/client.md#encryption-algorithm
        //= type=test
        //# The S3EC MUST validate that the configured encryption algorithm is not legacy.
        //= specification/s3-encryption/client.md#encryption-algorithm
        //= type=test
        //# If the configured encryption algorithm is legacy, then the S3EC MUST throw an exception.
        S3EncryptionClientException exception2 = assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF)
                .build());
        assertTrue(exception2.getMessage().contains("Encryption algorithm provided is LEGACY! Please specify a fully-supported encryption algorithm."));

        // Invalid Configurations

        //= specification/s3-encryption/client.md#key-commitment
        //= type=test
        //# The S3EC MUST validate the configured Encryption Algorithm against the provided key commitment policy.
        //= specification/s3-encryption/client.md#key-commitment
        //= type=test
        //# If the configured Encryption Algorithm is incompatible with the key commitment policy, then it MUST throw an exception.
        S3EncryptionClientException exception3 = assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .build());
        assertTrue(exception3.getMessage().contains("Encryption algorithm provided is LEGACY! Please specify a fully-supported encryption algorithm."));
        S3EncryptionClientException exception4 = assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .build());
        assertTrue(exception4.getMessage().contains("Encryption algorithm provided is LEGACY! Please specify a fully-supported encryption algorithm."));

        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
        S3EncryptionClientException exception5 = assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .build());
        assertTrue(exception5.getMessage().contains("The commitment policy forbids encryption with committing algorithm suites, but the specified encryption algorithm supports key commitment."));
        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
        S3EncryptionClientException exception6 = assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .build());
        assertTrue(exception6.getMessage().contains("The commitment policy requires encryption with a committing algorithm suite, but the specified encryption algorithm does not support key commitment."));
        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
        S3EncryptionClientException exception7 = assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                .build());
        assertTrue(exception7.getMessage().contains("The commitment policy requires encryption with a committing algorithm suite, but the specified encryption algorithm does not support key commitment."));

    }


    @Test
    public void testCommitmentPolicyForbidEncryptAllowDecrypt() {
        final String objectKey = appendTestSuffix("commitment-policy-forbid-encrypt-allow-decrypt");

        // Create clients with all three commitment policies
        S3Client forbidClient = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        S3Client requireAllowClient = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                .build();

        S3Client requireRequireClient = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                .build();

        // Test FORBID client encryption and decryption by all clients
        final String input = "CommitmentPolicyForbidEncryptAllowDecrypt";
        forbidClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        Map<String, String> metadata = forbidClient.headObject(HeadObjectRequest.builder().bucket(BUCKET).key(objectKey).build()).metadata();
        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST NOT encrypt using an algorithm suite which supports key commitment.
        assertTrue(ContentMetadataDecodingStrategy.isV1V2InObjectMetadata(metadata));
        assertFalse(ContentMetadataDecodingStrategy.isV3InObjectMetadata(metadata));
        assertEquals(metadata.get(MetadataKeyConstants.CONTENT_CIPHER),
                AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherName());

        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
        // FORBID client should be able to decrypt its own encryption
        ResponseBytes<GetObjectResponse> forbidResponse = forbidClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        assertEquals(input, forbidResponse.asUtf8String());

        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
        // REQUIRE_ALLOW client should be able to decrypt FORBID encryption (allows legacy)
        ResponseBytes<GetObjectResponse> requireAllowResponse = requireAllowClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        assertEquals(input, requireAllowResponse.asUtf8String());

        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST NOT allow decryption using algorithm suites which do not support key commitment.
        // REQUIRE_REQUIRE client should NOT be able to decrypt FORBID encryption (requires commitment)
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> requireRequireClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));
        assertTrue(exception.getMessage().contains("Commitment policy violation, decryption requires a committing algorithm suite, but the object was encrypted with a non-committing algorithm."));

        // Cleanup
        deleteObject(BUCKET, objectKey, forbidClient);
        forbidClient.close();
        requireAllowClient.close();
        requireRequireClient.close();
    }

    @Test
    public void testCommitmentPolicyRequireEncryptAllowDecrypt() {
        final String objectKey = appendTestSuffix("commitment-policy-require-encrypt-allow-decrypt");

        // Create clients with all three commitment policies
        S3Client forbidClient = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        S3Client requireAllowClient = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                .build();

        S3Client requireRequireClient = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                .build();

        // Test REQUIRE_ALLOW client encryption and decryption by all clients
        final String input = "CommitmentPolicyRequireEncryptAllowDecrypt";
        requireAllowClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        Map<String, String> metadata = requireAllowClient.headObject(HeadObjectRequest.builder().bucket(BUCKET).key(objectKey).build()).metadata();
        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
        assertTrue(ContentMetadataDecodingStrategy.isV3InObjectMetadata(metadata));
        assertFalse(ContentMetadataDecodingStrategy.isV1V2InObjectMetadata(metadata));
        assertEquals(metadata.get(MetadataKeyConstants.CONTENT_CIPHER_V3), AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.idAsString());

        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
        // FORBID client should be able to decrypt its own encryption
        ResponseBytes<GetObjectResponse> forbidResponse = forbidClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        assertEquals(input, forbidResponse.asUtf8String());

        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
        // REQUIRE_ALLOW client should be able to decrypt FORBID encryption (allows legacy)
        ResponseBytes<GetObjectResponse> requireAllowResponse = requireAllowClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        assertEquals(input, requireAllowResponse.asUtf8String());

        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST NOT allow decryption using algorithm suites which do not support key commitment.
        // REQUIRE_REQUIRE client should NOT be able to decrypt FORBID encryption (requires commitment)
        ResponseBytes<GetObjectResponse> requireRequireResponse = requireRequireClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        assertEquals(input, requireRequireResponse.asUtf8String());

        // Cleanup
        deleteObject(BUCKET, objectKey, requireAllowClient);
        forbidClient.close();
        requireAllowClient.close();
        requireRequireClient.close();
    }

    @Test
    public void testCommitmentPolicyRequireEncryptRequireDecrypt() {
        final String objectKey = appendTestSuffix("commitment-policy-require-encrypt-require-decrypt");

        // Create clients with all three commitment policies
        S3Client forbidClient = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .build();

        S3Client requireAllowClient = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                .build();

        S3Client requireRequireClient = S3EncryptionClient.builderV4()
                .aesKey(AES_KEY)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                .build();

        // Test REQUIRE_REQUIRE client encryption and decryption by all clients
        final String input = "CommitmentPolicyRequireEncryptRequireDecrypt";
        requireRequireClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        Map<String, String> metadata = requireAllowClient.headObject(HeadObjectRequest.builder().bucket(BUCKET).key(objectKey).build()).metadata();
        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
        assertTrue(ContentMetadataDecodingStrategy.isV3InObjectMetadata(metadata));
        assertFalse(ContentMetadataDecodingStrategy.isV1V2InObjectMetadata(metadata));
        assertEquals(metadata.get(MetadataKeyConstants.CONTENT_CIPHER_V3), AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.idAsString());

        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
        // FORBID client should be able to decrypt its own encryption
        ResponseBytes<GetObjectResponse> forbidResponse = forbidClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        assertEquals(input, forbidResponse.asUtf8String());

        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
        // REQUIRE_ALLOW client should be able to decrypt FORBID encryption (allows legacy)
        ResponseBytes<GetObjectResponse> requireAllowResponse = requireAllowClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        assertEquals(input, requireAllowResponse.asUtf8String());

        //= specification/s3-encryption/key-commitment.md#commitment-policy
        //= type=test
        //# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST NOT allow decryption using algorithm suites which do not support key commitment.
        // REQUIRE_REQUIRE client should NOT be able to decrypt FORBID encryption (requires commitment)
        ResponseBytes<GetObjectResponse> requireRequireResponse = requireRequireClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        assertEquals(input, requireRequireResponse.asUtf8String());

        // Cleanup
        deleteObject(BUCKET, objectKey, requireRequireClient);
        forbidClient.close();
        requireAllowClient.close();
        requireRequireClient.close();
    }
}
