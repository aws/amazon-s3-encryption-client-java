package software.amazon.encryption.s3.examples;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.encryption.s3.S3AsyncEncryptionClient;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AsyncClientExample {
    public static final String OBJECT_KEY = "async-client-example";

    // This example generates a new key. In practice, you would
    // retrieve your key from an existing keystore.
    private static final SecretKey AES_KEY = retrieveAesKey();

    public static void main(final String[] args) {
        String bucket = args[0];
        AsyncClient(bucket);
        cleanup(bucket);
    }

    public static void AsyncClient(String bucket) {
        final String input = "PutAsyncGetAsync";

        // Instantiate the S3 Async Encryption Client to encrypt and decrypt
        // by specifying an AES Key with the aesKey builder parameter.
        //
        // This means that the S3 Async Encryption Client can perform both encrypt and decrypt operations
        // as part of the S3 putObject and getObject operations.
        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        CompletableFuture<PutObjectResponse> futurePut = v3AsyncClient.putObject(builder -> builder
                .bucket(bucket)
                .key(OBJECT_KEY)
                .build(), AsyncRequestBody.fromString(input));
        // Block on completion of the futurePut
        futurePut.join();

        CompletableFuture<ResponseBytes<GetObjectResponse>> futureGet = v3AsyncClient.getObject(builder -> builder
                .bucket(bucket)
                .key(OBJECT_KEY)
                .build(), AsyncResponseTransformer.toBytes());
        // Just wait for the future to complete
        ResponseBytes<GetObjectResponse> getResponse = futureGet.join();
        assertEquals(input, getResponse.asUtf8String());
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
        S3AsyncClient v3Client = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Call deleteObject to delete the object from given S3 Bucket
        v3Client.deleteObject(builder -> builder.bucket(bucket)
                .key(OBJECT_KEY)).join();

        // Close the client
        v3Client.close();
    }
}
