// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.encryption.s3.examples.migration.v3;

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
 * Migration Step 0: This example demonstrates use of the S3 Encryption Client for Java v3
 * and is the starting state for migrating your data to the v4 client.
 * <p>
 * This example's purpose is to model behavior of an existing v3 client.
 * Subsequent migration steps will demonstrate code changes needed to use the v4 client.
 * <p>
 * This example configures a v3 client to:
 * - Write objects using non-key committing encryption algorithms
 * - Read objects encrypted with either key committing algorithms or with non-key committing algorithms
 * <p>
 * In this configuration, the client can read objects encrypted
 * with non-key committing algorithms (written by this v3 client or an in-progress v4 migration),
 * as well as objects encrypted by a migrated v4 client
 * that is configured to write objects encrypted with key committing algorithms.
 * You should ensure you are using the latest version of the v3 client
 * that can read objects encrypted with key committing algorithms before proceeding with migration.
 */
public class V3MigrationStep0 {

    private static final int CURRENT_MIGRATION_STEP = 0;

    public static void runMigrationExample(String bucketName, String objectKey, String kmsKeyId, String region)
            throws Exception {
        runMigrationExample(bucketName, objectKey, kmsKeyId, region, CURRENT_MIGRATION_STEP);
    }

    public static void runMigrationExample(String bucketName, String objectKey, String kmsKeyId, String region,
                                           int sourceStep) throws Exception {
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

        // Create S3 Encryption Client v3 with FORBID_ENCRYPT_ALLOW_DECRYPT commitment policy (default)
        // This is the default commitment policy for v3 clients
        // that can read objects encrypted with key commitment;
        // you do not need to set this explicitly.
        // However, setting this explicitly helps avoid accidental use of a v3 client
        // that cannot read objects encrypted with key committing algorithms.
        S3EncryptionClient encryptionClient = S3EncryptionClient.builderV4()
                .keyring(keyring)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .build();

        // Create object keys for PUT and GET operations
        // PUT: Always use current step
        String putObjectKey = String.format("%s-step-%d", objectKey, CURRENT_MIGRATION_STEP);
        // GET: Use sourceStep (debug parameter to test cross-compatibility between steps; defaults to current step)
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
