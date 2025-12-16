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
 * Migration Step 2: This example demonstrates how to update your v4 client configuration
 * to start writing objects encrypted with key committing algorithms.
 * <p>
 * This example's purpose is to demonstrate the commitment policy code changes required to
 * start writing objects encrypted with key committing algorithms
 * and document the behavioral changes that will result from this change.
 * <p>
 * When starting from a v4 client modeled in "Migration Step 1",
 * "Migration Step 2" WILL result in behavioral changes to your application.
 * The client will start writing objects encrypted with key committing algorithms.
 * <p>
 * IMPORTANT: You MUST have updated your readers to be able to read objects encrypted with key committing algorithms
 * before deploying the changes in this step.
 * This means deploying the changes from either "Migration Step 0" (if readers are v3 clients)
 * or "Migration Step 1" (if readers are v4 clients) to all of your readers
 * before deploying the changes to "Migration Step 2".
 * <p>
 * Once you deploy this change to your writers, your readers will start seeing
 * some objects encrypted with non-key committing algorithms,
 * and some objects encrypted with key committing algorithms.
 * Because the changes would have already been deployed to all readers from earlier migration steps,
 * we can be sure that our entire system is ready to read both types of objects.
 * After deploying these changes but before proceeding to "Migration Step 3",
 * you MUST take extra steps to ensure that your system is no longer reading
 * objects encrypted with non-key committing algorithms
 * (such as re-encrypting any existing objects using key committing algorithms).
 */
public class V4MigrationStep2 {

    private static final int CURRENT_MIGRATION_STEP = 2;

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

        // Create S3 Encryption Client v4 with REQUIRE_ENCRYPT_ALLOW_DECRYPT commitment policy
        // Migration note: The commitment policy has been updated to REQUIRE_ENCRYPT_ALLOW_DECRYPT.
        // This change causes the client to start writing objects encrypted with key committing algorithms.
        // The client will continue to be able to read objects encrypted with either
        // key committing or non-key committing algorithms.
        S3EncryptionClient encryptionClient = S3EncryptionClient.builderV4()
                .keyring(keyring)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                .build();

        // Create object keys for PUT and GET operations
        // PUT: Always use current step
        String putObjectKey = String.format("%s-step-%d", objectKey, CURRENT_MIGRATION_STEP);
        // GET: Use sourceStep (debug parameter to test cross-compatibility between steps; defaults to 2)
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
