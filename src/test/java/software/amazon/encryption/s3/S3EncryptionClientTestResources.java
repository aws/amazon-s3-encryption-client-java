package software.amazon.encryption.s3;

/**
 * Determines which AWS resources to use while running tests.
 */
public class S3EncryptionClientTestResources {

    public static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");
    public static final String KMS_KEY_ID = System.getenv("AWS_S3EC_TEST_KMS_KEY_ID");
    // This alias must point to the same key as KMS_KEY_ID
    public static final String KMS_KEY_ALIAS = System.getenv("AWS_S3EC_TEST_KMS_KEY_ALIAS");

}
