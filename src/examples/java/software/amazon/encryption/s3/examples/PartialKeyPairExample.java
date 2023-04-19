// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.examples;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.Delete;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;

public class PartialKeyPairExample {

    private static final String OBJECT_CONTENT = "Hello, world!";

    // Use unique object keys for each example
    private static final String PUBLIC_AND_PRIVATE_KEY_OBJECT_KEY = appendTestSuffix("PublicAndPrivateKeyTestObject");
    private static final String PUBLIC_KEY_OBJECT_KEY = appendTestSuffix("PublicKeyTestObject");
    private static final String PRIVATE_KEY_OBJECT_KEY = appendTestSuffix("PrivateKeyTestObject");

    private static final Set<ObjectIdentifier> PARTIAL_KEY_PAIR_EXAMPLE_OBJECT_KEYS = Stream
            .of(PUBLIC_AND_PRIVATE_KEY_OBJECT_KEY, PUBLIC_KEY_OBJECT_KEY, PRIVATE_KEY_OBJECT_KEY)
            .map(k -> ObjectIdentifier.builder().key(k).build())
            .collect(Collectors.toSet());

    // This example generates a new key. In practice, you would
    // retrieve your key from an existing keystore.
    private static final KeyPair RSA_KEY_PAIR = retrieveRsaKeyPair();

    public static void main(final String[] args) {
        final String bucket = args[0];

        useBothPublicAndPrivateKey(bucket);
        useOnlyPublicKey(bucket);
        useOnlyPrivateKey(bucket);
        cleanup(bucket);
    }

    public static void useBothPublicAndPrivateKey(final String bucket) {
        // Instantiate the S3 Encryption Client to encrypt and decrypt
        // by specifying an RSA wrapping key pair with the rsaKeyPair builder
        // parameter.
        // This means that the S3 Encryption Client can perform both encrypt and decrypt operations
        // as part of the S3 putObject and getObject operations.
        S3Client s3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        // Call putObject to encrypt the object and upload it to S3
        s3Client.putObject(PutObjectRequest.builder()
                .bucket(bucket)
                .key(PUBLIC_AND_PRIVATE_KEY_OBJECT_KEY)
                .build(), RequestBody.fromString(OBJECT_CONTENT));

        // Call getObject to retrieve and decrypt the object from S3
        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .key(PUBLIC_AND_PRIVATE_KEY_OBJECT_KEY));
        String output = objectResponse.asUtf8String();

        // Verify that the decrypted object matches the original plaintext object
        assertEquals(OBJECT_CONTENT, output, "Decrypted response does not match original plaintext!");

        // Close the client
        s3Client.close();
    }

    static void useOnlyPublicKey(final String bucket) {
        // Instantiate the S3 Encryption client to encrypt by specifying the
        // public key from an RSA key pair with the PartialKeyPair object.
        // When you specify the public key alone, all GetObject calls will fail
        // because the private key is required to decrypt.
        S3Client s3Client = S3EncryptionClient.builder()
                .rsaKeyPair(new PartialRsaKeyPair(null, RSA_KEY_PAIR.getPublic()))
                .build();

        // Call putObject to encrypt the object and upload it to S3
        s3Client.putObject(PutObjectRequest.builder()
                .bucket(bucket)
                .key(PUBLIC_KEY_OBJECT_KEY)
                .build(), RequestBody.fromString(OBJECT_CONTENT));

        // Attempt to call getObject to retrieve and decrypt the object from S3.
        try {
            s3Client.getObjectAsBytes(builder -> builder
                    .bucket(bucket)
                    .key(PUBLIC_KEY_OBJECT_KEY));
            fail("Expected exception! No private key provided for decryption.");
        } catch (final S3EncryptionClientException exception) {
            // This is expected; the s3Client cannot successfully call getObject
            // when instantiated with a public key.
        }

        // Close the client
        s3Client.close();
    }

    static void useOnlyPrivateKey(final String bucket) {

        // Instantiate the S3 Encryption client to decrypt by specifying the
        // private key from an RSA key pair with the PartialRsaKeyPair object.
        // When you specify the private key alone, all PutObject calls will
        // fail because the public key is required to encrypt.
        S3Client s3ClientPrivateKeyOnly = S3EncryptionClient.builder()
                .rsaKeyPair(new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), null))
                .build();

        // Attempt to call putObject to encrypt the object and upload it to S3
        try {
            s3ClientPrivateKeyOnly.putObject(PutObjectRequest.builder()
                    .bucket(bucket)
                    .key(PRIVATE_KEY_OBJECT_KEY)
                    .build(), RequestBody.fromString(OBJECT_CONTENT));
            fail("Expected exception! No public key provided for encryption.");
        } catch (final S3EncryptionClientException exception) {
            // This is expected; the s3Client cannot successfully call putObject
            // when instantiated with a private key.
        }

        // Instantiate a new S3 Encryption client with a public key in order
        // to successfully call PutObject so that the client which only has
        // a private key can call GetObject on a valid S3 Object.
        S3Client s3ClientPublicKeyOnly = S3EncryptionClient.builder()
                .rsaKeyPair(new PartialRsaKeyPair(null, RSA_KEY_PAIR.getPublic()))
                .build();

        // Call putObject to encrypt the object and upload it to S3
        s3ClientPublicKeyOnly.putObject(PutObjectRequest.builder()
                .bucket(bucket)
                .key(PRIVATE_KEY_OBJECT_KEY)
                .build(), RequestBody.fromString(OBJECT_CONTENT));

        // Call getObject to retrieve and decrypt the object from S3
        ResponseBytes<GetObjectResponse> objectResponse = s3ClientPrivateKeyOnly.getObjectAsBytes(builder -> builder
                .bucket(bucket)
                .key(PRIVATE_KEY_OBJECT_KEY));
        String output = objectResponse.asUtf8String();

        // Verify that the decrypted object matches the original plaintext object
        assertEquals(OBJECT_CONTENT, output, "The decrypted response does not match the original plaintext!");

        // Close the clients
        s3ClientPublicKeyOnly.close();
        s3ClientPrivateKeyOnly.close();
    }

    public static void cleanup(final String bucket) {
        // The S3 Encryption client is not required when deleting encrypted
        // objects, use the S3 Client.
        final S3Client s3Client = S3Client.builder().build();
        final Delete delete = Delete.builder()
                .objects(PARTIAL_KEY_PAIR_EXAMPLE_OBJECT_KEYS)
                .build();
        s3Client.deleteObjects(builder -> builder
                .bucket(bucket)
                .delete(delete)
                .build());

        // Close the client
        s3Client.close();
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