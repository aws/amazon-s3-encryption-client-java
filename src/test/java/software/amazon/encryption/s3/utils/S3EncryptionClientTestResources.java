package software.amazon.encryption.s3.utils;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.Delete;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;

/**
 * Determines which AWS resources to use while running tests.
 */
public class S3EncryptionClientTestResources {

    public static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");
    public static final String KMS_KEY_ID = System.getenv("AWS_S3EC_TEST_KMS_KEY_ID");
    // This alias must point to the same key as KMS_KEY_ID
    public static final String KMS_KEY_ALIAS = System.getenv("AWS_S3EC_TEST_KMS_KEY_ALIAS");

    /**
     * Delete the object for the given objectKey in the given bucket.
     * @param bucket the bucket to delete the object from
     * @param objectKey the key of the object to delete
     */
    public static void deleteObject(final String bucket, final String objectKey, final S3Client s3Client) {
        final Delete delete = Delete.builder()
                .objects(ObjectIdentifier.builder().key(objectKey).build())
                .build();
        s3Client.deleteObjects(builder -> builder
                .bucket(bucket)
                .delete(delete)
                .build());
    }
}
