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
 * Migration Step 3: This example demonstrates how to update your v4 client configuration
 * to stop reading objects encrypted with non-key committing algorithms.
 * <p>
 * This example's purpose is to demonstrate the commitment policy code changes required to
 * stop reading objects encrypted with non-key committing algorithms
 * and document the behavioral changes that will result from this change.
 * <p>
 * When starting from a v4 client modeled in "Migration Step 2",
 * "Migration Step 3" WILL result in behavioral changes to your application.
 * The client will no longer be able to read objects encrypted with non-key committing algorithms.
 * Before deploying these changes, you MUST have taken some extra steps
 * to ensure that your system is no longer reading such objects,
 * such as re-encrypting them with key committing algorithms.
 * <p>
 * IMPORTANT: Before deploying the changes in this step, your system should not be reading
 * any objects encrypted with non-key committing algorithms.
 * The changes in this step will cause such read attempts to fail.
 * This means the changes from "Migration Step 2" should have already been deployed to all of your readers
 * before you deploy the changes from "Migration Step 3".
 * <p>
 * Once you complete Step 3, you can be sure that all items being read by your system
 * have been encrypted using key committing algorithms.
 */
public class V4MigrationStep3 {

    private static final int CURRENT_MIGRATION_STEP = 3;

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

        // Create S3 Encryption Client v4 with REQUIRE_ENCRYPT_REQUIRE_DECRYPT commitment policy
        // Migration note: The commitment policy has been changed to REQUIRE_ENCRYPT_REQUIRE_DECRYPT.
        // This change causes the client to stop reading objects encrypted without key committing algorithms.
        // IMPORTANT: Ensure your system is no longer reading such objects before deploying this change.
        // REQUIRE_ENCRYPT_REQUIRE_DECRYPT is also the default commitment policy for v4 clients,
        // so you do not need to set this explicitly (this is the same as Step 2, but with confirmation
        // that no legacy objects are being read).
        S3EncryptionClient encryptionClient = S3EncryptionClient.builderV4()
                .keyring(keyring)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
                .build();

        // Create object keys for PUT and GET operations
        // PUT: Always use current step
        String putObjectKey = String.format("%s-step-%d", objectKey, CURRENT_MIGRATION_STEP);
        // GET: Use sourceStep (debug parameter to test cross-compatibility between steps; defaults to 3)
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
