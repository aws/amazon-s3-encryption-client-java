// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.utils;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.Credentials;

import java.util.concurrent.CompletableFuture;

/**
 * Determines which AWS resources to use while running tests.
 */
public class S3EncryptionClientTestResources {

    public static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");
    public static final String KMS_KEY_ID = System.getenv("AWS_S3EC_TEST_KMS_KEY_ID");
    // This alias must point to the same key as KMS_KEY_ID
    public static final String KMS_KEY_ALIAS = System.getenv("AWS_S3EC_TEST_KMS_KEY_ALIAS");
    public static final Region KMS_REGION = Region.getRegion(Regions.fromName(System.getenv("AWS_REGION")));
    // Alternate role to test credential configuration and access denied behavior
    public static final String ALTERNATE_ROLE_ARN = System.getenv("AWS_S3EC_TEST_ALT_ROLE_ARN");
    // Alternate KMS key, which only the alternate role has access to
    public static final String ALTERNATE_KMS_KEY = System.getenv("AWS_S3EC_TEST_ALT_KMS_KEY_ARN");


    /**
     * Creds provider for the "alternate" role which is useful for testing cred configuration
     * and access denied behavior.
     */
    public static class AlternateRoleCredentialsProvider implements AwsCredentialsProvider {

        StsClient stsClient_;

        public AlternateRoleCredentialsProvider() {
            super();
            stsClient_ = StsClient.create();
        }

        @Override
        public AwsCredentials resolveCredentials() {
            String sessionName = "s3ec-test" + DateTimeFormat.forPattern("-yyMMdd-hhmmss").print(new DateTime());
            Credentials assumeRoleCreds = stsClient_.assumeRole(builder -> builder
              .roleArn(ALTERNATE_ROLE_ARN).roleSessionName(sessionName).build()).credentials();
            return AwsSessionCredentials.create(assumeRoleCreds.accessKeyId(),
              assumeRoleCreds.secretAccessKey(),
              assumeRoleCreds.sessionToken());
        }
    }

    public static class NullCredentialsProvider implements AwsCredentialsProvider {

        public NullCredentialsProvider() {
            super();
        }

        @Override
        public AwsCredentials resolveCredentials() {
            return AwsBasicCredentials
              .create(null, null);
        }
    }

    /**
     * For a given string, append a suffix to distinguish it from
     * simultaneous test runs.
     * @param s
     * @return
     */
    public static String appendTestSuffix(final String s) {
        StringBuilder stringBuilder = new StringBuilder(s);
        stringBuilder.append(DateTimeFormat.forPattern("-yyMMdd-hhmmss-").print(new DateTime()));
        stringBuilder.append((int) (Math.random() * 100000));
        return stringBuilder.toString();
    }

    /**
     * Delete the object for the given objectKey in the given bucket.
     * @param bucket the bucket to delete the object from
     * @param objectKey the key of the object to delete
     */
    public static void deleteObject(final String bucket, final String objectKey, final S3Client s3Client) {
        s3Client.deleteObject(builder -> builder
                .bucket(bucket)
                .key(objectKey)
                .build());
    }

    /**
     * Delete the object for the given objectKey in the given bucket.
     * @param bucket the bucket to delete the object from
     * @param objectKey the key of the object to delete
     */
    public static void deleteObject(final String bucket, final String objectKey, final S3AsyncClient s3Client) {
        CompletableFuture<DeleteObjectResponse> response = s3Client.deleteObject(builder -> builder
                .bucket(bucket)
                .key(objectKey));
        // Ensure completion before return
        response.join();
    }
}
