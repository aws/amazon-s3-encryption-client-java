package software.amazon.encryption.s3.examples;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class PartialKeyPairExample {

    private static final String OBJECT_KEY = "MyEncryptedObject";
    private static final String OBJECT_CONTENT = "Hello, world!";

    // This example generates a new key. In practice, you would
    // retrieve your key from an existing keystore.
    private static final KeyPair RSA_KEY_PAIR = retrieveRsaKeyPair();

    public static void main(final String[] args) {

        final String bucket = args[0];

        useBothPublicAndPrivateKey(bucket);
        useOnlyPublicKey(bucket);
        useOnlyPrivateKey(bucket);
    }

    public static void useBothPublicAndPrivateKey(final String bucket) {
        // 1. Instantiate the S3 Encryption Client using its builder.
        // This configures the S3 Encryption Client to use an RSA Key Pair
        // as the wrapping key pair for data key encryption.
        // In this example, the KeyPair object is provided directly to the builder.
        // This means that the S3 Encryption Client can perform both encrypt and decrypt operations,
        // which correspond to putObject and getObject operations in S3.
        S3Client s3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        // Call putObject to encrypt the data and then put it in S3
        s3Client.putObject(PutObjectRequest.builder()
                .bucket(bucket)
                .key(OBJECT_KEY)
                .build(), RequestBody.fromString(OBJECT_CONTENT));

        // Call getObject to retrieve and decrypt the data from S3
        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .key(OBJECT_KEY));
        String output = objectResponse.asUtf8String();

        // Verify that the decrypted response matches the original input plaintext
        if (!output.equals(OBJECT_CONTENT)) {
            throw new AssertionError("Decrypted response does not match original plaintext!");
        }
    }

    static void useOnlyPublicKey(final String bucket) {
        // 1. Instantiate the S3 Encryption Client using its builder.
        // This configures the S3 Encryption Client to use only the public key
        // portion of the RSA key. Instead of providing the key pair directly,
        // a PartialRsaKeyPair object is instantiated using only the public key.
        // This means that the S3 Encryption Client can only perform encryption,
        // meaning it can call putObject but not getObject, because the private key
        // is needed for decryption.
        S3Client s3Client = S3EncryptionClient.builder()
                .rsaKeyPair(new PartialRsaKeyPair(null, RSA_KEY_PAIR.getPublic()))
                .build();

        // Call putObject to encrypt the data and then put it in S3
        s3Client.putObject(PutObjectRequest.builder()
                .bucket(bucket)
                .key(OBJECT_KEY)
                .build(), RequestBody.fromString(OBJECT_CONTENT));

        // Attempt to call getObject to retrieve and decrypt the data from S3.
        try {
            s3Client.getObjectAsBytes(builder -> builder
                    .bucket(bucket)
                    .key(OBJECT_KEY));
        } catch (final S3EncryptionClientException exception) {
            // This is expected; the s3Client as configured cannot successfully call getObject
        }

    }

    static void useOnlyPrivateKey(final String bucket) {
        // 1. Instantiate the S3 Encryption Client using its builder.
        // This configures the S3 Encryption Client to use only the private key
        // portion of the RSA key. Instead of providing the key pair directly,
        // a PartialRsaKeyPair object is instantiated using only the private key.
        // This means that the S3 Encryption Client can only perform decryption,
        // meaning it can call getObject but not putObject, because the public key
        // is needed for encryption.
        S3Client s3Client = S3EncryptionClient.builder()
                .rsaKeyPair(new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), null))
                .build();

        // Attempt to call putObject to encrypt the data and then put it in S3
        try {
            s3Client.putObject(PutObjectRequest.builder()
                    .bucket(bucket)
                    .key(OBJECT_KEY)
                    .build(), RequestBody.fromString(OBJECT_CONTENT));
        } catch (final S3EncryptionClientException exception) {
            // This is expected; the s3Client as configured cannot successfully call putObject
        }

        // Call getObject to retrieve and decrypt the data from S3
        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .key(OBJECT_KEY));
        String output = objectResponse.asUtf8String();

        // Verify that the decrypted response matches the original input plaintext
        if (!output.equals(OBJECT_CONTENT)) {
            throw new AssertionError("The decrypted response does not match the original plaintext!");
        }
    }

    private static KeyPair retrieveRsaKeyPair() {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            return keyPairGen.generateKeyPair();
        } catch (final NoSuchAlgorithmException exception) {
            // This should be impossible, wrap with a runtime exception
            throw new RuntimeException(exception);
        }
    }

}