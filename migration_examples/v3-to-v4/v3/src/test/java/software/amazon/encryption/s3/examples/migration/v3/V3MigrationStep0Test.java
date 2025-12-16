// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.encryption.s3.examples.migration.v3;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.regions.Region;

/**
 * Test for V3 Migration Step 0 example.
 * This test requires AWS credentials and resources to be configured via environment variables.
 */
public class V3MigrationStep0Test {

    private static final String BUCKET_NAME = System.getenv("AWS_S3EC_TEST_BUCKET");
    private static final String KMS_KEY_ID = System.getenv("AWS_S3EC_TEST_KMS_KEY_ID");
    private static final String REGION = System.getenv("AWS_REGION");
    private static final String TEST_OBJECT_KEY = "migration-test-v3-" + ((int) (Math.random() * 100000));

    @Test
    public void testV3MigrationStep0() throws Exception {
        // Successfully executes step 0
        // Step 0 writes without key commitment
        V3MigrationStep0.runMigrationExample(BUCKET_NAME, TEST_OBJECT_KEY, KMS_KEY_ID, REGION, 0);
    }

    @AfterAll
    public static void cleanupTestObjects() {
        try (S3Client s3Client = S3Client.builder()
                .region(Region.of(REGION))
                .build()) {
            // Delete object created by step 0
            String objectKey = String.format("%s-step-%d", TEST_OBJECT_KEY, 0);
            s3Client.deleteObject(DeleteObjectRequest.builder()
                    .bucket(BUCKET_NAME)
                    .key(objectKey)
                    .build());
        }
    }
}
