package software.amazon.encryption.s3.examples;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;

public class RangedGetExample {

    // Create a 200 character input string to use as your object in the following examples.
    private static final String OBJECT_CONTENT = "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST" +
            "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST" +
            "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST" +
            "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST" +
            "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST";
    private static final String OBJECT_KEY =  appendTestSuffix("RangedGetObject");

    // This example generates a new key. In practice, you would
    // retrieve your key from an existing keystore.
    private static final SecretKey AES_KEY = retrieveAesKey();

    public static void main(final String[] args) {
        final String bucket = args[0];

        putObjectToPerformRangedGet(bucket);

        simpleAesGcmV3RangedGet(bucket);
        aesGcmV3RangedGetOperations(bucket);
        failsWhenRangeExceedsObjectLength(bucket);

        cleanup(bucket);
    }

    private static void putObjectToPerformRangedGet(String bucket) {
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Call putObject to encrypt the object and upload it to S3
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(bucket)
                .key(OBJECT_KEY)
                .build(), RequestBody.fromString(OBJECT_CONTENT));

        // Close the client
        v3Client.close();
    }

    public static void simpleAesGcmV3RangedGet(String bucket) {
        // Instantiate the S3 Encryption Client by specifying an AES Key with the aesKey builder parameter.
        // You must also specify the enableLegacyUnauthenticatedModes parameter to enable ranged GET requests.
        //
        // This means that the S3 Encryption Client can perform both encrypt and decrypt operations,
        // and can perform ranged GET requests when a range is provided.
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Call getObject to retrieve a range of 10-20 bytes from the object content.
        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("bytes=10-20")
                .key(OBJECT_KEY));
        String output = objectResponse.asUtf8String();

        // Verify that the decrypted object range matches the original plaintext object at the same range.
        // Note: The start and end indices of the byte range are included in the returned object.
        assertEquals(OBJECT_CONTENT.substring(10, 20 + 1), output);
    }

    public static void aesGcmV3RangedGetOperations(String bucket) {
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // 1. Call getObject to retrieve a range of 190-300 bytes,
        // where 190 is within object range but 300 is outside the original plaintext object range.
        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("bytes=190-300")
                .key(OBJECT_KEY));
        String output = objectResponse.asUtf8String();

        // Verify that when the start index is within object range and the end index is out of range,
        // the S3 Encryption Client returns the object from the start index to the end of the original plaintext object.
        assertEquals(OBJECT_CONTENT.substring(190), output);

        // 2. Call getObject to retrieve a range of 100-50 bytes,
        // where the start index is greater than the end index.
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("bytes=100-50")
                .key(OBJECT_KEY));
        output = objectResponse.asUtf8String();

        // Verify that when the start index is greater than the end index,
        // the S3 Encryption Client returns the entire object.
        assertEquals(OBJECT_CONTENT, output);

        // 3. Call getObject to retrieve a range of 10-20 bytes but with invalid format
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("10-20")
                .key(OBJECT_KEY));
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
                .key(OBJECT_KEY));
        output = objectResponse.asUtf8String();

        // Verify that when both the start and end indices are greater than the original plaintext object's total length,
        // but still within the same cipher block, the Amazon S3 Encryption Client returns an empty object.
        assertEquals("", output);

        // Close the client
        v3Client.close();
    }

    public static void failsWhenRangeExceedsObjectLength(String bucket) {
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Attempt to call getObject with range 300-400.
        // Both the start and end indices are greater than the original plaintext object's total length, 200,
        // and are outside the object's cipher block.
        try {
            v3Client.getObjectAsBytes(builder -> builder
                    .bucket(bucket)
                    .key(OBJECT_KEY)
                    .range("bytes=300-400"));
            fail("Expected exception! Since given range is out of range with plaintext object range of 200");
        } catch (final S3EncryptionClientException exception) {
            // This is expected; the s3Client cannot successfully call getObject
            // with given range exceeding object length, Throws S3Exception
        }

        // Close the client
        v3Client.close();
    }

    private static SecretKey retrieveAesKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            return keyGen.generateKey();
        } catch (final NoSuchAlgorithmException exception) {
            // This should be impossible, wrap with a runtime exception
            throw new RuntimeException(exception);
        }
    }

    private static void cleanup(String bucket) {
        // Instantiate the client to delete object
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Call deleteObject to delete the object from given S3 Bucket
        v3Client.deleteObject(builder -> builder.bucket(bucket)
                .key(OBJECT_KEY));

        // Close the client
        v3Client.close();
    }
}
