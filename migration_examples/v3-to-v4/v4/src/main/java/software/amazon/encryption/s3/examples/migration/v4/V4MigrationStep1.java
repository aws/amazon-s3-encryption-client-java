// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.encryption.s3.examples.migration.v4;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.CommitmentPolicy;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.KmsKeyring;

/**
 * Migration Step 1: This example demonstrates how to start using the S3 Encryption Client v4.
 * <p>
 * This example's purpose is to demonstrate the code changes to
 * migrate from the v3 client to the v4 client while maintaining identical behavior.
 * <p>
 * When starting from a v3 client modeled in "Migration Step 0",
 * "Migration Step 1" should result in no behavioral changes to your application.
 * <p>
 * In this example we configure a v4 client to:
 * - Write objects encrypted with non-key committing algorithms
 * - Read objects encrypted either with or without key committing algorithms
 * <p>
 * In this configuration, the client will continue to read objects encrypted
 * with non-key committing algorithms (written by a v3 client or this migration-in-progress v4 client),
 * as well as objects encrypted by a migrated v4 client
 * that is configured to write objects encrypted with key committing algorithms.
 * <p>
 * This configuration results in identical behavior to the S3 Encryption Client v3 client
 * configured to use the default FORBID_ENCRYPT_ALLOW_DECRYPT commitment policy.
 */
public class V4MigrationStep1 {

    private static final int CURRENT_MIGRATION_STEP = 1;

    public static void runMigrationExample(String bucketName, String objectKey, String kmsKeyId, String region) {
        runMigrationExample(bucketName, objectKey, kmsKeyId, region, CURRENT_MIGRATION_STEP);
    }

    public static void runMigrationExample(String bucketName, String objectKey, String kmsKeyId, String region,
                                           int sourceStep) {
        // Test data for encryption
        String testData = "Hello, World! This is a test message for S3 encryption client migration.";

        // Create regular S3 client
        S3Client s3Client = S3Client.builder()
                .region(Region.of(region))
                .build();

        // Create KMS client
        KmsClient kmsClient = KmsClient.builder()
                .region(Region.of(region))
                .build();

        // Create KMS keyring
        KmsKeyring keyring = KmsKeyring.builder()
                .kmsClient(kmsClient)
                .wrappingKeyId(kmsKeyId)
                .build();

        // Create S3 Encryption Client v4 with FORBID_ENCRYPT_ALLOW_DECRYPT commitment policy
        // Migration note: This is now the v4 client API
        // This MUST be explicitly configured to FORBID_ENCRYPT_ALLOW_DECRYPT.
        // While FORBID_ENCRYPT_ALLOW_DECRYPT is the default for v3 clients,
        // v4 clients default to REQUIRE_ENCRYPT_REQUIRE_DECRYPT.
        // This configuration ensures identical behavior to a v3 client.
        S3EncryptionClient encryptionClient = S3EncryptionClient.builderV4()
                .keyring(keyring)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .build();

        // Create object keys for PUT and GET operations
        // PUT: Always use current step
        String putObjectKey = String.format("%s-step-%d", objectKey, CURRENT_MIGRATION_STEP);
        // GET: Use sourceStep (debug parameter to test cross-compatibility between steps; defaults to 1)
        String getObjectKey = String.format("%s-step-%d", objectKey, sourceStep);

        // Upload encrypted object using S3 Encryption Client
        encryptionClient.putObject(
                PutObjectRequest.builder()
                        .bucket(bucketName)
                        .key(putObjectKey)
                        .build(),
                RequestBody.fromString(testData));

        // Download and decrypt object using S3 Encryption Client
        String decryptedData = encryptionClient.getObject(
                GetObjectRequest.builder()
                        .bucket(bucketName)
                        .key(getObjectKey)
                        .build(),
                ResponseTransformer.toBytes()
        ).asUtf8String();

        // Verify the roundtrip was successful
        if (!decryptedData.equals(testData)) {
            throw new AssertionError(
                    String.format("Roundtrip failed - data mismatch. Original: %s, Decrypted: %s",
                            testData, decryptedData));
        }

        // Clean up resources
        encryptionClient.close();
        kmsClient.close();
    }

    public static void main(String[] args) throws Exception {
        String bucketName = args[0];
        String objectKey = args[1];
        String kmsKeyId = args[2];
        String region = args[3];
        runMigrationExample(bucketName, objectKey, kmsKeyId, region);
    }
}
