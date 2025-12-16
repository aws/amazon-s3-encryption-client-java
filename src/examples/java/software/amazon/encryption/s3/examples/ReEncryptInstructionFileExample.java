// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.examples;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.S3EncryptionClient.withCustomInstructionFileSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.internal.InstructionFileConfig;
import software.amazon.encryption.s3.internal.ReEncryptInstructionFileRequest;
import software.amazon.encryption.s3.internal.ReEncryptInstructionFileResponse;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.MaterialsDescription;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;
import software.amazon.encryption.s3.materials.RsaKeyring;

public class ReEncryptInstructionFileExample {

  /**
   * Generates a 256-bit AES key for encryption/decryption operations.
   *
   * @return A SecretKey instance for AES operations
   * @throws NoSuchAlgorithmException if AES algorithm is not available
   */
  private static SecretKey generateAesKey() throws NoSuchAlgorithmException {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(256);
    return keyGen.generateKey();
  }

  /**
   * Generates a 2048-bit RSA key pair for encryption/decryption operations.
   *
   * @return A KeyPair instance for RSA operations
   * @throws NoSuchAlgorithmException if RSA algorithm is not available
   */
  private static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(2048);
    return keyPairGen.generateKeyPair();
  }

  public static void main(final String[] args) throws NoSuchAlgorithmException {
    final String bucket = args[0];
    simpleAesKeyringReEncryptInstructionFile(bucket);
    simpleRsaKeyringReEncryptInstructionFile(bucket);
    simpleRsaKeyringReEncryptInstructionFileWithCustomSuffix(bucket);
  }

  /**
   * This example demonstrates re-encrypting the encrypted data key in an instruction file with a new AES wrapping key.
   *
   * @param bucket The name of the Amazon S3 bucket to perform operations on.
   * @throws NoSuchAlgorithmException if AES algorithm is not available
   */
  public static void simpleAesKeyringReEncryptInstructionFile(
    final String bucket
  ) throws NoSuchAlgorithmException {
    // Set up the S3 object key and content to be encrypted
    final String objectKey = appendTestSuffix(
      "aes-re-encrypt-instruction-file-test"
    );
    final String input =
      "Testing re-encryption of instruction file with AES Keyring";

    // Generate the original AES key for initial encryption
    SecretKey originalAesKey = generateAesKey();

    // Sample metadata for AES keyring identification and context - not used for encryption/decryption purposes
    // Helps distinguish between the old and new AES keyrings during the reEncryptInstructionFile operation
    MaterialsDescription originalMaterialsDescription = MaterialsDescription
      .builder()
      .put("version", "1.0")
      .put("rotated", "no")
      .build();

    // Create the original AES keyring with materials description
    AesKeyring oldKeyring = AesKeyring
      .builder()
      .wrappingKey(originalAesKey)
      .materialsDescription(originalMaterialsDescription)
      .build();

    // Create a default S3 client for instruction file operations
    S3Client wrappedClient = S3Client.create();

    // Create the S3 Encryption Client with instruction file support enabled
    // The client can perform both putObject and getObject operations using the original AES key
    S3EncryptionClient originalClient = S3EncryptionClient
      .builderV4()
      .keyring(oldKeyring)
      .instructionFileConfig(
        InstructionFileConfig
          .builder()
          .instructionFileClient(wrappedClient)
          .enableInstructionFilePutObject(true)
          .build()
      )
      .build();

    // Upload both the encrypted object and instruction file to the specified bucket in S3
    originalClient.putObject(
      builder -> builder.bucket(bucket).key(objectKey).build(),
      RequestBody.fromString(input)
    );

    // Generate a new AES key for re-encryption (rotating wrapping key)
    SecretKey newAesKey = generateAesKey();

    // Sample metadata for rotated AES keyring identification and context - not used for encryption/decryption purposes
    // Helps distinguish between the old and new AES keyrings during the reEncryptInstructionFile operation
    MaterialsDescription newMaterialsDescription = MaterialsDescription
      .builder()
      .put("version", "2.0")
      .put("rotated", "yes")
      .build();

    // Create a new keyring with the new AES key and updated materials description
    AesKeyring newKeyring = AesKeyring
      .builder()
      .wrappingKey(newAesKey)
      .materialsDescription(newMaterialsDescription)
      .build();

    // Create the re-encryption of instruction file request to re-encrypt the encrypted data key with the new wrapping key
    // This updates the instruction file without touching the encrypted object
    ReEncryptInstructionFileRequest reEncryptInstructionFileRequest =
      ReEncryptInstructionFileRequest
        .builder()
        .bucket(bucket)
        .key(objectKey)
        .newKeyring(newKeyring)
        .enforceRotation(true)
        .build();

    // Perform the re-encryption of the instruction file
    ReEncryptInstructionFileResponse response =
      originalClient.reEncryptInstructionFile(reEncryptInstructionFileRequest);

    // Verify that the original client can no longer decrypt the object
    // This proves that the instruction file has been successfully re-encrypted
    try {
      originalClient.getObjectAsBytes(builder ->
        builder.bucket(bucket).key(objectKey).build()
      );
      throw new RuntimeException(
        "Original client should not be able to decrypt the object in S3 post re-encryption of instruction file!"
      );
    } catch (S3EncryptionClientException e) {
      assertTrue(e.getMessage().contains("Unable to AES/GCM unwrap"));
    }

    // Create a new client with the rotated AES key
    S3EncryptionClient newClient = S3EncryptionClient
      .builderV4()
      .keyring(newKeyring)
      .instructionFileConfig(
        InstructionFileConfig
          .builder()
          .instructionFileClient(wrappedClient)
          .enableInstructionFilePutObject(true)
          .build()
      )
      .build();

    // Verify that the new client can successfully decrypt the object
    // This proves that the instruction file has been successfully re-encrypted
    ResponseBytes<GetObjectResponse> decryptedObject =
      newClient.getObjectAsBytes(builder ->
        builder.bucket(bucket).key(objectKey).build()
      );

    // Assert that the decrypted object's content matches the original input
    assertEquals(input, decryptedObject.asUtf8String());

    // Call deleteObject to delete the object from given S3 Bucket
    deleteObject(bucket, objectKey, originalClient);
  }

  /**
   * This example demonstrates re-encrypting the encrypted data key in an instruction file with a new RSA wrapping key.
   *
   * @param bucket The name of the Amazon S3 bucket to perform operations on.
   * @throws NoSuchAlgorithmException if RSA algorithm is not available
   */
  public static void simpleRsaKeyringReEncryptInstructionFile(
    final String bucket
  ) throws NoSuchAlgorithmException {
    // Set up the S3 object key and content to be encrypted
    final String objectKey = appendTestSuffix(
      "rsa-re-encrypt-instruction-file-test"
    );
    final String input =
      "Testing re-encryption of instruction file with RSA Keyring";

    // Generate the original RSA key pair for initial encryption
    KeyPair originalRsaKeyPair = generateRsaKeyPair();
    PublicKey originalPublicKey = originalRsaKeyPair.getPublic();
    PrivateKey originalPrivateKey = originalRsaKeyPair.getPrivate();

    // Create a partial RSA key pair for the original keyring
    PartialRsaKeyPair originalPartialRsaKeyPair = PartialRsaKeyPair
      .builder()
      .publicKey(originalPublicKey)
      .privateKey(originalPrivateKey)
      .build();

    // Sample metadata for RSA keyring identification and context - not used for encryption/decryption purposes
    // Helps distinguish between the old and new RSA keyrings during the reEncryptInstructionFile operation
    MaterialsDescription originalMaterialsDescription = MaterialsDescription
      .builder()
      .put("version", "1.0")
      .put("rotated", "no")
      .build();

    // Create the original RSA keyring with materials description
    RsaKeyring originalKeyring = RsaKeyring
      .builder()
      .wrappingKeyPair(originalPartialRsaKeyPair)
      .materialsDescription(originalMaterialsDescription)
      .build();

    // Create a default S3 client for instruction file operations
    S3Client wrappedClient = S3Client.create();

    // Create the S3 Encryption Client with instruction file support enabled
    // The client can perform both putObject and getObject operations using RSA keyring
    S3EncryptionClient originalClient = S3EncryptionClient
      .builderV4()
      .keyring(originalKeyring)
      .instructionFileConfig(
        InstructionFileConfig
          .builder()
          .instructionFileClient(wrappedClient)
          .enableInstructionFilePutObject(true)
          .build()
      )
      .build();

    // Upload both the encrypted object and instruction file to the specified bucket in S3
    originalClient.putObject(
      builder -> builder.bucket(bucket).key(objectKey).build(),
      RequestBody.fromString(input)
    );

    // Generate a new RSA key pair for the new RSA keyring
    KeyPair newKeyPair = generateRsaKeyPair();
    PublicKey newPublicKey = newKeyPair.getPublic();
    PrivateKey newPrivateKey = newKeyPair.getPrivate();

    // Create a partial RSA key pair for the new RSA keyring
    PartialRsaKeyPair newPartialRsaKeyPair = PartialRsaKeyPair
      .builder()
      .publicKey(newPublicKey)
      .privateKey(newPrivateKey)
      .build();

    // Sample metadata for rotated RSA keyring identification and context - not used for encryption/decryption purposes
    // Helps distinguish between the old and new RSA keyrings during the reEncryptInstructionFile operation
    MaterialsDescription newMaterialsDescription = MaterialsDescription
      .builder()
      .put("version", "2.0")
      .put("rotated", "yes")
      .build();

    // Create the new RSA keyring with updated materials description
    RsaKeyring newKeyring = RsaKeyring
      .builder()
      .wrappingKeyPair(newPartialRsaKeyPair)
      .materialsDescription(newMaterialsDescription)
      .build();

    // Create the re-encryption of instruction file request to re-encrypt the encrypted data key with the new wrapping key
    // This updates the instruction file without touching the encrypted object
    ReEncryptInstructionFileRequest reEncryptInstructionFileRequest =
      ReEncryptInstructionFileRequest
        .builder()
        .bucket(bucket)
        .key(objectKey)
        .newKeyring(newKeyring)
        .enforceRotation(true)
        .build();

    // Perform the re-encryption of the instruction file
    ReEncryptInstructionFileResponse reEncryptInstructionFileResponse =
      originalClient.reEncryptInstructionFile(reEncryptInstructionFileRequest);

    // Verify that the original client can no longer decrypt the object
    // This proves that the instruction file has been successfully re-encrypted
    try {
      originalClient.getObjectAsBytes(builder ->
        builder.bucket(bucket).key(objectKey).build()
      );
      throw new RuntimeException(
        "Original client should not be able to decrypt the object in S3 post re-encryption of instruction file!"
      );
    } catch (S3EncryptionClientException e) {
      assertTrue(e.getMessage().contains("Unable to RSA-OAEP-SHA1 unwrap"));
    }

    // Create a new client with the rotated RSA key
    S3EncryptionClient newClient = S3EncryptionClient
      .builderV4()
      .keyring(newKeyring)
      .instructionFileConfig(
        InstructionFileConfig
          .builder()
          .instructionFileClient(wrappedClient)
          .enableInstructionFilePutObject(true)
          .build()
      )
      .build();

    // Verify that the new client can successfully decrypt the object
    // This proves that the instruction file has been successfully re-encrypted
    ResponseBytes<GetObjectResponse> decryptedObject =
      newClient.getObjectAsBytes(builder ->
        builder.bucket(bucket).key(objectKey).build()
      );

    // Assert that the decrypted object's content matches the original input
    assertEquals(input, decryptedObject.asUtf8String());

    // Call deleteObject to delete the object from given S3 Bucket
    deleteObject(bucket, objectKey, originalClient);
  }

  /**
   * This example demonstrates generating a custom instruction file to enable access to encrypted object by a third party.
   * It showcases a scenario where:
   *  1. The original client encrypts and uploads an object to S3.
   *  2. The original client wants to share this encrypted object with a third party client without sharing their private key.
   *  3. A new instruction file is created specifically for the third party client, containing the data key encrypted with the third party's public key.
   *  4. The third party client can then access and decrypt the object using their own private key and custom instruction file.
   *  5. The original client can still access and decrypt the object using their own private key and instruction file.
   *
   * @param bucket The name of the Amazon S3 bucket to perform operations on.
   * @throws NoSuchAlgorithmException if RSA algorithm is not available
   */
  public static void simpleRsaKeyringReEncryptInstructionFileWithCustomSuffix(
    final String bucket
  ) throws NoSuchAlgorithmException {
    // Set up the S3 object key and content to be encrypted
    final String objectKey = appendTestSuffix(
      "rsa-re-encrypt-instruction-file-test-with-custom-suffix"
    );
    final String input =
      "Testing re-encryption of instruction file with RSA Keyring";

    // Generate RSA key pair for the original client
    KeyPair clientRsaKeyPair = generateRsaKeyPair();
    PublicKey clientPublicKey = clientRsaKeyPair.getPublic();
    PrivateKey clientPrivateKey = clientRsaKeyPair.getPrivate();

    // Create a partial RSA key pair for the client's keyring
    PartialRsaKeyPair clientPartialRsaKeyPair = PartialRsaKeyPair
      .builder()
      .publicKey(clientPublicKey)
      .privateKey(clientPrivateKey)
      .build();

    // Sample metadata for client keyring identification and context - not used for encryption/decryption purposes
    // Helps distinguish between the client and third party RSA keyrings during the reEncryptInstructionFile operation
    MaterialsDescription clientMaterialsDescription = MaterialsDescription
      .builder()
      .put("isOwner", "yes")
      .put("access-level", "admin")
      .build();

    // Create the client's RSA keyring with materials description
    RsaKeyring clientKeyring = RsaKeyring
      .builder()
      .wrappingKeyPair(clientPartialRsaKeyPair)
      .materialsDescription(clientMaterialsDescription)
      .build();

    // Create a default S3 client for instruction file operations
    S3Client wrappedClient = S3Client.create();

    // Create the S3 Encryption Client with instruction file support enabled
    // The client can perform both putObject and getObject operations using RSA keyring
    S3EncryptionClient client = S3EncryptionClient
      .builderV4()
      .keyring(clientKeyring)
      .instructionFileConfig(
        InstructionFileConfig
          .builder()
          .instructionFileClient(wrappedClient)
          .enableInstructionFilePutObject(true)
          .build()
      )
      .build();

    // Upload both the encrypted object and instruction file to the specified bucket in S3
    client.putObject(
      builder -> builder.bucket(bucket).key(objectKey).build(),
      RequestBody.fromString(input)
    );

    // Generate a new RSA key pair for the third party customer
    KeyPair thirdPartyKeyPair = generateRsaKeyPair();
    PublicKey thirdPartyPublicKey = thirdPartyKeyPair.getPublic();
    PrivateKey thirdPartyPrivateKey = thirdPartyKeyPair.getPrivate();

    // Create a partial RSA key pair for the third party's decryption keyring
    PartialRsaKeyPair thirdPartyPartialRsaKeyPair = PartialRsaKeyPair
      .builder()
      .publicKey(thirdPartyPublicKey)
      .privateKey(thirdPartyPrivateKey)
      .build();

    // Sample metadata for third party keyring identification and context - not used for encryption/decryption purposes
    // Helps distinguish between the client and third party RSA keyrings during the reEncryptInstructionFile operation
    MaterialsDescription thirdPartyMaterialsDescription = MaterialsDescription
      .builder()
      .put("isOwner", "no")
      .put("access-level", "user")
      .build();

    // Create RSA keyring with third party's public key and updated materials description for re-encryption request
    RsaKeyring sharedKeyring = RsaKeyring
      .builder()
      .wrappingKeyPair(
        PartialRsaKeyPair.builder().publicKey(thirdPartyPublicKey).build()
      )
      .materialsDescription(thirdPartyMaterialsDescription)
      .build();

    // Create RSA keyring with third party's public and private keys for decryption purposes with updated materials description
    RsaKeyring thirdPartyKeyring = RsaKeyring
      .builder()
      .wrappingKeyPair(thirdPartyPartialRsaKeyPair)
      .materialsDescription(
        MaterialsDescription
          .builder()
          .put("isOwner", "no")
          .put("access-level", "user")
          .build()
      )
      .build();

    // Create the re-encryption request that will generate a new instruction file specifically for third party access
    // This new instruction file will use a custom suffix and contain the data key encrypted with the third party's public key
    ReEncryptInstructionFileRequest reEncryptInstructionFileRequest =
      ReEncryptInstructionFileRequest
        .builder()
        .bucket(bucket)
        .key(objectKey)
        .instructionFileSuffix("third-party-access-instruction-file") // Custom instruction file suffix for third party
        .newKeyring(sharedKeyring)
        .build();

    // Perform the re-encryption operation to create the new instruction file
    // This creates a new instruction file without modifying the original encrypted object
    ReEncryptInstructionFileResponse reEncryptInstructionFileResponse =
      client.reEncryptInstructionFile(reEncryptInstructionFileRequest);

    // Create the third party's S3 Encryption Client
    S3EncryptionClient thirdPartyClient = S3EncryptionClient
      .builderV4()
      .keyring(thirdPartyKeyring)
      .instructionFileConfig(
        InstructionFileConfig
          .builder()
          .instructionFileClient(wrappedClient)
          .enableInstructionFilePutObject(true)
          .build()
      )
      .build();

    // Verify that the original client can still decrypt the object in the specified bucket in S3 using the default instruction file
    ResponseBytes<GetObjectResponse> clientDecryptedObject =
      client.getObjectAsBytes(builder ->
        builder.bucket(bucket).key(objectKey).build()
      );

    // Assert that the decrypted object's content matches the original input
    assertEquals(input, clientDecryptedObject.asUtf8String());

    // Verify that the third party cannot decrypt the object in the specified bucket in S3 using the default instruction file
    try {
      ResponseBytes<GetObjectResponse> thirdPartyDecryptObject =
        thirdPartyClient.getObjectAsBytes(builder ->
          builder.bucket(bucket).key(objectKey).build()
        );
      throw new RuntimeException(
        "Third party client should not be able to decrypt the object in S3 using the default instruction file!"
      );
    } catch (S3EncryptionClientException e) {
      assertTrue(e.getMessage().contains("Unable to RSA-OAEP-SHA1 unwrap"));
    }

    // Verify that the third party can decrypt the object in the specified bucket in S3 using their custom instruction file
    // This demonstrates successful secure sharing of encrypted data
    ResponseBytes<GetObjectResponse> thirdPartyDecryptedObject =
      thirdPartyClient.getObjectAsBytes(builder ->
        builder
          .bucket(bucket)
          .key(objectKey)
          .overrideConfiguration(
            withCustomInstructionFileSuffix(
              ".third-party-access-instruction-file"
            )
          )
          .build()
      );

    // Assert that the decrypted object's content matches the original input
    assertEquals(input, thirdPartyDecryptedObject.asUtf8String());

    // Call deleteObject to delete the object from given S3 Bucket
    deleteObject(bucket, objectKey, client);
  }
}
