package software.amazon.encryption.s3.examples;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.encryption.s3.S3AsyncEncryptionClient;

import java.util.concurrent.CompletableFuture;

public class AsyncClientExample {
    public static final String OBJECT_KEY = appendTestSuffix("async-client-example");

    public static void main(final String[] args) {
        String bucket = args[0];
        AsyncClient(bucket);
        cleanup(bucket);
    }

    /**
     * This example demonstrates handling of an Asynchronous S3 Encryption Client for interacting with an Amazon S3 bucket, performing
     * both encryption and decryption using the AWS KMS Key Arn for secure object storage.
     *
     * @param bucket The name of the Amazon S3 bucket to perform operations on.
     */
    public static void AsyncClient(String bucket) {
        final String input = "PutAsyncGetAsync";

        // Instantiate the S3 Async Encryption Client to encrypt and decrypt
        // by specifying an AES Key with the aesKey builder parameter.
        //
        // This means that the S3 Async Encryption Client can perform both encrypt and decrypt operations
        // as part of the S3 putObject and getObject operations.
        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // Call putObject to encrypt the object and upload it to S3
        CompletableFuture<PutObjectResponse> futurePut = v3AsyncClient.putObject(builder -> builder
                .bucket(bucket)
                .key(OBJECT_KEY)
                .build(), AsyncRequestBody.fromString(input));
        // Block on completion of the futurePut
        futurePut.join();

        // Call getObject to retrieve and decrypt the object from S3
        CompletableFuture<ResponseBytes<GetObjectResponse>> futureGet = v3AsyncClient.getObject(builder -> builder
                .bucket(bucket)
                .key(OBJECT_KEY)
                .build(), AsyncResponseTransformer.toBytes());
        // Just wait for the future to complete
        ResponseBytes<GetObjectResponse> getResponse = futureGet.join();

        // Assert
        assertEquals(input, getResponse.asUtf8String());

        // Close the client
        v3AsyncClient.close();
    }

    private static void cleanup(String bucket) {
        // Instantiate the client to delete object
        S3AsyncClient v3Client = S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        // Call deleteObject to delete the object from given S3 Bucket
        v3Client.deleteObject(builder -> builder.bucket(bucket)
                .key(OBJECT_KEY)).join();

        // Close the client
        v3Client.close();
    }
}
