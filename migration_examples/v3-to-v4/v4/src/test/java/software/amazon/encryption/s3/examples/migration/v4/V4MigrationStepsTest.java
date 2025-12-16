// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.encryption.s3.examples.migration.v4;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.regions.Region;
import software.amazon.encryption.s3.S3EncryptionClientException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for V4 Migration Step examples.
 * These tests require AWS credentials and resources to be configured via environment variables.
 */
public class V4MigrationStepsTest {

    private static final String BUCKET_NAME = System.getenv("AWS_S3EC_TEST_BUCKET");
    private static final String KMS_KEY_ID = System.getenv("AWS_S3EC_TEST_KMS_KEY_ID");
    private static final String REGION = System.getenv("AWS_REGION");
    private static final String TEST_OBJECT_KEY = "migration-test-v4-" + ((int) (Math.random() * 100000));

    @Test
    public void testV4MigrationStep1() {
        // Successfully executes step 1
        // Step 1 writes without key commitment
        V4MigrationStep1.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 1);

        // Given: Step 2 has succeeded (writes with key commitment)
        V4MigrationStep2.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 2);

        // When: Execute Step 1 with sortReadValue=2, Then: Success (i.e. can read values written with key commitment)
        V4MigrationStep1.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 2);

        // Given: Step 3 has succeeded (writes with key commitment)
        V4MigrationStep3.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 3);

        // When: Execute Step 1 with sortReadValue=3, Then: Success (i.e. can read values written with key commitment)
        V4MigrationStep1.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 3);
    }

    @Test
    public void testV4MigrationStep2() {
        // Successfully executes step 2
        // Step 2 writes with key commitment
        V4MigrationStep2.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 2);

        // Given: Step 1 has succeeded (writes without key commitment)
        V4MigrationStep1.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 1);

        // When: Execute Step 2 with sortReadValue=1, Then: Success (i.e. can read values written without key commitment)
        V4MigrationStep2.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 1);

        // Given: Step 3 has succeeded (writes with key commitment)
        V4MigrationStep3.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 3);

        // When: Execute Step 2 with sortReadValue=3, Then: Success (i.e. can read values written with key commitment)
        V4MigrationStep2.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 3);
    }

    @Test
    public void testV4MigrationStep3() {
        // Successfully executes step 3
        // Step 3 writes with key commitment
        V4MigrationStep3.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 3);

        // Given: Step 1 has succeeded (writes without key commitment)
        V4MigrationStep1.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 1);

        // When: Execute Step 3 with sortReadValue=1, Then: Fails with commitment policy violation
        // (i.e. cannot read values written without key commitment)
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () ->
            V4MigrationStep3.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 1)
        );
        assertTrue(exception.getMessage().contains("Commitment policy violation"),
                "Expected commitment policy violation message, but got: " + exception.getMessage());

        // Given: Step 2 has succeeded (writes with key commitment)
        V4MigrationStep2.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 2);

        // When: Execute Step 3 with sortReadValue=2, Then: Success (i.e. can read values written with key commitment)
        V4MigrationStep3.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 2);
    }

    @AfterAll
    public static void cleanupTestObjects() {
        try (S3Client s3Client = S3Client.builder()
                .region(Region.of(REGION))
                .build()) {
            // Delete objects created by each migration step
            for (int step = 1; step <= 3; step++) {
                String objectKey = String.format("%s-step-%d", TEST_OBJECT_KEY, step);
                s3Client.deleteObject(DeleteObjectRequest.builder()
                        .bucket(BUCKET_NAME)
                        .key(objectKey)
                        .build());
            }
        }
    }
}
