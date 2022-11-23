package software.amazon.encryption.s3.examples;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class RangedGetExample {

    // Creates a 200 Character Input String
    private static final String OBJECT_CONTENT = "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST" +
            "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST" +
            "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST" +
            "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST" +
            "abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST";
    private static final String OBJECT_KEY = "RangedGetObject";

    // This example generates a new key. In practice, you would
    // retrieve your key from an existing keystore.
    private static final SecretKey AES_KEY = retrieveAesKey();

    public static void main(final String[] args) {
        final String bucket = args[0];

        putObjectToPerformRangedGet(bucket);

        failsOnRangeWhenLegacyModeDisabled(bucket);
        aesGcmV3RangedGetOperations(bucket);
        failsWhenRangeExceedsObjectLength(bucket);

        cleanup(bucket);
    }

    private static void putObjectToPerformRangedGet(String bucket) {
        // Instantiate the S3 Encryption Client to encrypt and decrypt
        // by specifying an AES Key with the aesKey builder parameter.
        //
        // This means that the S3 Encryption Client can perform both encrypt and decrypt operations
        // as part of the S3 putObject and getObject operations.
        // Note: enableLegacyUnauthenticatedModes() is not required to perform putObject only.
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

    public static void failsOnRangeWhenLegacyModeDisabled(String bucket) {
        // Instantiate the S3 Encryption Client to encrypt and decrypt
        // by specifying an AES Key with the aesKey builder parameter,
        // but do not specify enableLegacyUnauthenticatedModes(), as it is disabled by default.
        //
        // This means that the S3 Encryption Client can perform both encrypt and decrypt operations
        // as part of the S3 putObject and getObject operations,
        // but throws an error if range is given with getObject call since enableLegacyUnauthenticatedModes is disabled by default.
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Attempt to call getObject with range to retrieve and decrypt the object from S3.
        try {
            v3Client.getObjectAsBytes(builder -> builder
                    .bucket(bucket)
                    .key(OBJECT_KEY)
                    .range("bytes=10-20"));
            fail("Expected exception! enableLegacyUnauthenticatedModes() is disabled during client configuration.");
        } catch (final S3EncryptionClientException exception) {
            // This is expected; the s3Client cannot successfully call getObject with range is given
            // when instantiated without enabling enableLegacyUnauthenticatedModes().
        }

        // close the client
        v3Client.close();
    }

    public static void aesGcmV3RangedGetOperations(String bucket) {

        // Instantiate the S3 Encryption Client to encrypt and decrypt
        // by specifying an AES Key with the aesKey builder parameter,
        // also enable enableLegacyUnauthenticatedModes() to perform Ranged-get operations.
        //
        // This means that the S3 Encryption Client can perform both encrypt and decrypt operations
        // as part of the S3 putObject and getObject operations,
        // also able to perform ranged-get if range is given with getObject call.
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // 1. Call getObject to retrieve a range of 10-20 bytes from the object content.
        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("bytes=10-20")
                .key(OBJECT_KEY));
        String output = objectResponse.asUtf8String();

        // Verify that the decrypted ranged-get object matches the original plaintext object with same range.
        // Note: Ranged Get returns the object with both the start and end indexes included.
        assertEquals(OBJECT_CONTENT.substring(10, 20+1), output);

        // 2. Call getObject to retrieve a range of 190-300 bytes,
        // where 190 is within object range but 300 is out of original plaintext object range.
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("bytes=190-300")
                .key(OBJECT_KEY));
        output = objectResponse.asUtf8String();

        // Verify that when range start index within object range and end index out of range,
        // returns object from start index of the given range to End of original plaintext object range.
        assertEquals(OBJECT_CONTENT.substring(190), output);

        // 3. Call getObject to retrieve a range of 100-50 bytes,
        // where start index is greater the end index of the range.
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("bytes=100-50")
                .key(OBJECT_KEY));
        output = objectResponse.asUtf8String();

        // Verify that the decrypted ranged-get object with
        // invalid range start index range greater than ending index, returns entire object.
        assertEquals(OBJECT_CONTENT, output);

        // 4. Call getObject to retrieve a range of 10-20 bytes but with invalid format
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("10-20")
                .key(OBJECT_KEY));
        output = objectResponse.asUtf8String();

        // Verify that the decrypted ranged-get object with invalid range format returns entire object.
        // Note: Range should always in the format of "bytes=i-j" where i is start index, j is end index
        assertEquals(OBJECT_CONTENT, output);

        // 5. Call getObject to retrieve a range of 216-217 bytes,
        // which is out of range with original plaintext object range of 200.
        objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .range("bytes=216-217")
                .key(OBJECT_KEY));
        output = objectResponse.asUtf8String();

        // Verify that the decrypted ranged-get object with range starting index and ending index greater than object length,
        // but within Cipher Block size, returns empty object
        assertEquals("", output);

        // Close the client
        v3Client.close();
    }

    public static void failsWhenRangeExceedsObjectLength(String bucket) {

        // Instantiate the S3 Encryption Client to encrypt and decrypt
        // by specifying an AES Key with the aesKey builder parameter,
        // also enable enableLegacyUnauthenticatedModes() to perform Ranged-get operations.
        //
        // This means that the S3 Encryption Client can perform both encrypt and decrypt operations
        // as part of the S3 putObject and getObject operations,
        // also able to perform ranged-get if range is given with getObject call.
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Attempt to call getObject with range 300-400 exceeding original plaintext object range of 200.
        try {
            v3Client.getObjectAsBytes(builder -> builder
                    .bucket(bucket)
                    .key(OBJECT_KEY)
                    .range("bytes=300-400"));
            fail("Expected exception! Since given range is out of range with plaintext object range of 200");
        } catch (final S3Exception exception) {
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
