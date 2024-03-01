package software.amazon.encryption.s3.examples;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClient;

public class RangedGetExample {

    // Create a 200 character input string to use as your object in the following examples.
    private static final String OBJECT_CONTENT = "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST" +
            "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST" +
            "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST" +
            "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST" +
            "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST";

    public static void main(final String[] args) {
        final String bucket = args[0];

        simpleAesGcmV3RangedGet(bucket);
        aesGcmV3RangedGetOperations(bucket);
    }

    /**
     * This example demonstrates handling of simple ranged GET to retrieve a part of the encrypted objects.
     *
     * @param bucket The name of the Amazon S3 bucket to perform operations on.
     */
    public static void simpleAesGcmV3RangedGet(String bucket) {
        final String objectKey = appendTestSuffix("simple-v3-ranged-get-example");

        // Instantiate the S3 Encryption Client by specifying an KMS Key with the kmsKeyId builder parameter.
        // You must also specify the `enableLegacyUnauthenticatedModes` parameter to enable ranged GET requests.
        //
        // This means that the S3 Encryption Client can perform both encrypt and decrypt operations,
        // and can perform ranged GET requests when a range is provided.
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Call putObject to encrypt the object and upload it to S3
        v3Client.putObject(PutObjectRequest.builder()
                                   .bucket(bucket)
                                   .key(objectKey)
                                   .build(), RequestBody.fromString(OBJECT_CONTENT));

        // Call getObject to retrieve a range of 10-20 bytes from the object content.
        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("bytes=10-20")
                .key(objectKey));
        String output = objectResponse.asUtf8String();

        // Verify that the decrypted object range matches the original plaintext object at the same range.
        // Note: The start and end indices of the byte range are included in the returned object.
        assertEquals(OBJECT_CONTENT.substring(10, 20 + 1), output);

        // Cleanup
        v3Client.deleteObject(builder -> builder.bucket(bucket).key(objectKey));
        v3Client.close();
    }

    /**
     * This example demonstrates handling of various unusual ranged GET scenarios when retrieving encrypted objects.
     *
     * @param bucket The name of the Amazon S3 bucket to perform operations on.
     */
    public static void aesGcmV3RangedGetOperations(String bucket) {
        final String objectKey = appendTestSuffix("aes-gcm-v3-ranged-get-examples");

        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Call putObject to encrypt the object and upload it to S3
        v3Client.putObject(PutObjectRequest.builder()
                                   .bucket(bucket)
                                   .key(objectKey)
                                   .build(), RequestBody.fromString(OBJECT_CONTENT));

        // 1. Call getObject to retrieve a range of 190-300 bytes,
        // where 190 is within object range but 300 is outside the original plaintext object range.
        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("bytes=190-300")
                .key(objectKey));
        String output = objectResponse.asUtf8String();

        // Verify that when the start index is within object range and the end index is out of range,
        // the S3 Encryption Client returns the object from the start index to the end of the original plaintext object.
        assertEquals(OBJECT_CONTENT.substring(190), output);

        // 2. Call getObject to retrieve a range of 100-50 bytes,
        // where the start index is greater than the end index.
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("bytes=100-50")
                .key(objectKey));
        output = objectResponse.asUtf8String();

        // Verify that when the start index is greater than the end index,
        // the S3 Encryption Client returns the entire object.
        assertEquals(OBJECT_CONTENT, output);

        // 3. Call getObject to retrieve a range of 10-20 bytes but with invalid format
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("10-20")
                .key(objectKey));
        output = objectResponse.asUtf8String();

        // Verify that when the range is specified with an invalid format,
        // the S3 Encryption Client returns the entire object.
        // Note: Your byte range should always be specified in the following format: "bytes=start–end"
        assertEquals(OBJECT_CONTENT, output);

        // 4. Call getObject to retrieve a range of 216-217 bytes.
        // Both the start and end indices are greater than the original plaintext object's total length, 200.
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("bytes=216-217")
                .key(objectKey));
        output = objectResponse.asUtf8String();

        // Verify that when both the start and end indices are greater than the original plaintext object's total length,
        // but still within the same cipher block, the Amazon S3 Encryption Client returns an empty object.
        assertEquals("", output);

        // 5. Call getObject to retrieve a range starting from byte 40 to the end of the object,
        // where the start index is within the object range, and the end index is unspecified.
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("bytes=40-")
                .key(objectKey));
        output = objectResponse.asUtf8String();

        // Verify that when the start index is specified without an end index,
        // the S3 Encryption Client returns the object from the start index to the end of the original plaintext object.
        assertEquals(OBJECT_CONTENT.substring(40), output);

        // Cleanup
        v3Client.deleteObject(builder -> builder.bucket(bucket).key(objectKey));
        v3Client.close();
    }
}
