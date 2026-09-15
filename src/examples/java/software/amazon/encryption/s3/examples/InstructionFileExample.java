package software.amazon.encryption.s3.examples;

import java.security.NoSuchAlgorithmException;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.internal.InstructionFileConfig;
import software.amazon.encryption.s3.materials.KmsKeyring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class InstructionFileExample {

    public static void main(final String[] args) throws NoSuchAlgorithmException {
        final String bucket = args[0];
        final String kmsKeyId = args.length > 1 ? args[1] : null;

        if (kmsKeyId != null) {
            InstructionFileExample.simpleKmsKeyringUseInstructionFile(bucket, kmsKeyId);
        }
    }
    /**
     * This example demonstrates using Instruction Files.
     *
     * @param bucket      The name of the Amazon S3 bucket to perform operations on.
     * @param kmsKeyId    The KMS key ID used for encryption
     */
    public static void simpleKmsKeyringUseInstructionFile(
        final String bucket,
        final String kmsKeyId
    ) {
        // Set up the S3 object key and content to be encrypted
        final String objectKey = appendTestSuffix(
            "kms-instruction-file-test"
        );
        final String input =
            "Testing encryption of instruction file with KMS Keyring";

        // Create a KMS client for key operations
        KmsClient kmsClient = KmsClient.create();

        // Create the original KMS keyring with the first KMS key
        KmsKeyring originalKeyring = KmsKeyring
            .builder()
            .kmsClient(kmsClient)
            .wrappingKeyId(kmsKeyId)
            .build();

        // Create a default S3 client for instruction file operations
        S3Client wrappedClient = S3Client.create();

        // Create the S3 Encryption Client with instruction file support enabled
        // The client can perform both putObject and getObject operations using the KMS key
        ResponseBytes<GetObjectResponse> decryptedObject;
        try (S3EncryptionClient s3ec = S3EncryptionClient
            .builderV4()
            .keyring(originalKeyring)
            .instructionFileConfig(
                InstructionFileConfig
                    .builder()
                    .instructionFileClient(wrappedClient)
                    .enableInstructionFilePutObject(true)
                    .build()
            ).build()) {

            // Upload both the encrypted object and instruction file to the specified bucket in S3
            s3ec.putObject(
                builder -> builder.bucket(bucket).key(objectKey).build(),
                RequestBody.fromString(input)
            );

            // Verify that the client can successfully decrypt the object
            decryptedObject = s3ec.getObjectAsBytes(builder ->
                builder.bucket(bucket).key(objectKey).build()
            );
            // Assert that the decrypted object's content matches the original input
            assertEquals(input, decryptedObject.asUtf8String());

            // Call deleteObject to delete the object and instruction file
            // from given S3 Bucket
            deleteObject(bucket, objectKey, s3ec);
        }
    }
}
