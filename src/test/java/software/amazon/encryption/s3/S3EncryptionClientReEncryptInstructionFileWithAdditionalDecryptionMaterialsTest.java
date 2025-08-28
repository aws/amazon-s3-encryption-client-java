// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.internal.InstructionFileConfig;
import software.amazon.encryption.s3.internal.ReEncryptInstructionFileRequest;
import software.amazon.encryption.s3.internal.ReEncryptInstructionFileResponse;
import software.amazon.encryption.s3.materials.AesKeyMaterial;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.MaterialsDescription;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;
import software.amazon.encryption.s3.materials.RawKeyMaterial;
import software.amazon.encryption.s3.materials.RsaKeyMaterial;
import software.amazon.encryption.s3.materials.RsaKeyring;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.S3EncryptionClient.withCustomInstructionFileSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

/**
 * This class tests the ReEncryptInstructionFile operation with additionalDecryptionMaterials.
 * It tests scenarios where the client is configured with additionalDecryptionMaterials and uses
 * those materials to decrypt the instruction file during the re-encryption process.
 */
public class S3EncryptionClientReEncryptInstructionFileWithAdditionalDecryptionMaterialsTest {

    private static SecretKey AES_KEY_1;
    private static SecretKey AES_KEY_2;
    private static SecretKey AES_KEY_3;
    private static KeyPair RSA_KEY_PAIR_1;
    private static KeyPair RSA_KEY_PAIR_2;
    private static KeyPair RSA_KEY_PAIR_3;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        // Generate AES keys
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY_1 = keyGen.generateKey();
        AES_KEY_2 = keyGen.generateKey();
        AES_KEY_3 = keyGen.generateKey();

        // Generate RSA key pairs
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        RSA_KEY_PAIR_1 = keyPairGen.generateKeyPair();
        RSA_KEY_PAIR_2 = keyPairGen.generateKeyPair();
        RSA_KEY_PAIR_3 = keyPairGen.generateKeyPair();
    }

    /**
     * Test AES keyring with additionalDecryptionMaterials for ReEncryptInstructionFile.
     * This test encrypts an object with AES_KEY_1, then uses a client with AES_KEY_2 as the primary key
     * but with additionalDecryptionMaterials containing AES_KEY_1 to re-encrypt the instruction file.
     */
    @Test
    public void testAesKeyringReEncryptInstructionFileWithAdditionalDecryptionMaterials() {
        // Create materials descriptions
        MaterialsDescription originalMatDesc = MaterialsDescription.builder()
                .put("purpose", "original")
                .put("version", "1")
                .build();

        MaterialsDescription newMatDesc = MaterialsDescription.builder()
                .put("purpose", "rotated")
                .put("version", "2")
                .build();

        MaterialsDescription otherMatDesc = MaterialsDescription.builder()
                .put("purpose", "testing")
                .put("do not use", "just for testing multi-key")
                .build();

        // Create a map of additional decryption key materials containing all the keys
        Map<MaterialsDescription, RawKeyMaterial<SecretKey>> additionalDecryptionKeyMaterial = new HashMap<>();
        additionalDecryptionKeyMaterial.put(originalMatDesc, RawKeyMaterial.<SecretKey>builder()
                .materialsDescription(originalMatDesc)
                .keyMaterial(AES_KEY_1)
                .build());
        additionalDecryptionKeyMaterial.put(newMatDesc, RawKeyMaterial.<SecretKey>builder()
                .materialsDescription(newMatDesc)
                .keyMaterial(AES_KEY_2)
                .build());
        additionalDecryptionKeyMaterial.put(otherMatDesc, AesKeyMaterial.aesBuilder()
                .materialsDescription(otherMatDesc)
                .keyMaterial(AES_KEY_3)
                .build());

        // Create an AES keyring with the first key and original materials description
        AesKeyring originalKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_1)
                .materialsDescription(originalMatDesc)
                .build();

        // Create an S3 client for the original encryption
        S3Client wrappedClient = S3Client.create();
        S3EncryptionClient originalClient = S3EncryptionClient.builder()
                .keyring(originalKeyring)
                .instructionFileConfig(
                        InstructionFileConfig.builder()
                                .instructionFileClient(wrappedClient)
                                .enableInstructionFilePutObject(true)
                                .build()
                )
                .build();

        // Create a test object key and content
        final String objectKey = appendTestSuffix("aes-re-encrypt-instruction-file-with-additional-decryption-materials");
        final String input = "Testing re-encryption of instruction file with AES Keyring and additional decryption materials";

        // Encrypt and upload the object with the original keyring
        originalClient.putObject(
                builder -> builder.bucket(BUCKET).key(objectKey).build(),
                RequestBody.fromString(input)
        );

        // Get the original instruction file to verify its contents
        ResponseBytes<GetObjectResponse> originalInstructionFile = wrappedClient.getObjectAsBytes(
                builder -> builder.bucket(BUCKET).key(objectKey + ".instruction").build()
        );

        // Parse the original instruction file
        String originalInstructionFileContent = originalInstructionFile.asUtf8String();
        JsonNodeParser parser = JsonNodeParser.create();
        JsonNode originalInstructionFileNode = parser.parse(originalInstructionFileContent);

        String originalIv = originalInstructionFileNode.asObject().get("x-amz-iv").asString();
        String originalEncryptedDataKeyAlgorithm = originalInstructionFileNode.asObject().get("x-amz-wrap-alg").asString();
        String originalEncryptedDataKey = originalInstructionFileNode.asObject().get("x-amz-key-v2").asString();
        JsonNode originalMatDescNode = parser.parse(originalInstructionFileNode.asObject().get("x-amz-matdesc").asString());

        assertEquals("original", originalMatDescNode.asObject().get("purpose").asString());
        assertEquals("1", originalMatDescNode.asObject().get("version").asString());

        // Create a new AES keyring with a different key as primary but with additionalDecryptionKeyMaterial containing the original key
        AesKeyring newKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_2) // Key used to ReEncrypt
                .materialsDescription(newMatDesc)
                .additionalDecryptionKeyMaterial(additionalDecryptionKeyMaterial) // contains the original key
                .build();

        // Create a client with the new keyring
        S3EncryptionClient newClient = S3EncryptionClient.builder()
                .keyring(newKeyring)
                .instructionFileConfig(
                        InstructionFileConfig.builder()
                                .instructionFileClient(wrappedClient)
                                .enableInstructionFilePutObject(true)
                                .build()
                )
                .build();

        // Re-encrypt the instruction file with the new keyring
        ReEncryptInstructionFileRequest reEncryptRequest = ReEncryptInstructionFileRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .newKeyring(newKeyring)
                .build();

        // The re-encryption should succeed because the new client contains the original key in additionalDecryptionMaterials
        ReEncryptInstructionFileResponse response = newClient.reEncryptInstructionFile(reEncryptRequest);

        // Verify the response
        assertEquals(BUCKET, response.bucket());
        assertEquals(objectKey, response.key());
        assertEquals("instruction", response.instructionFileSuffix());

        // Get the re-encrypted instruction file to verify its contents
        ResponseBytes<GetObjectResponse> reEncryptedInstructionFile = wrappedClient.getObjectAsBytes(
                builder -> builder.bucket(BUCKET).key(objectKey + ".instruction").build()
        );

        // Parse the re-encrypted instruction file
        String reEncryptedInstructionFileContent = reEncryptedInstructionFile.asUtf8String();
        JsonNode reEncryptedInstructionFileNode = parser.parse(reEncryptedInstructionFileContent);

        String reEncryptedIv = reEncryptedInstructionFileNode.asObject().get("x-amz-iv").asString();
        String reEncryptedDataKeyAlgorithm = reEncryptedInstructionFileNode.asObject().get("x-amz-wrap-alg").asString();
        String reEncryptedDataKey = reEncryptedInstructionFileNode.asObject().get("x-amz-key-v2").asString();
        JsonNode reEncryptedMatDescNode = parser.parse(reEncryptedInstructionFileNode.asObject().get("x-amz-matdesc").asString());

        // Verify the re-encrypted instruction file has the new materials description
        assertEquals("rotated", reEncryptedMatDescNode.asObject().get("purpose").asString());
        assertEquals("2", reEncryptedMatDescNode.asObject().get("version").asString());

        // Verify the IV is preserved but the encrypted data key is different
        assertEquals(originalIv, reEncryptedIv);
        assertEquals(originalEncryptedDataKeyAlgorithm, reEncryptedDataKeyAlgorithm);
        assertNotEquals(originalEncryptedDataKey, reEncryptedDataKey);

        // Verify decryption works with the new client (already created above)

        // Verify the object can be decrypted with the new key
        ResponseBytes<GetObjectResponse> decryptedObject = newClient.getObjectAsBytes(
                GetObjectRequest.builder().bucket(BUCKET).key(objectKey).build()
        );
        assertEquals(input, decryptedObject.asUtf8String());

        // Verify the original client can no longer decrypt the object with the original keyring
        try {
            originalClient.getObjectAsBytes(
                    GetObjectRequest.builder().bucket(BUCKET).key(objectKey).build()
            );
            assertTrue(false, "Original client should not be able to decrypt the re-encrypted object");
        } catch (S3EncryptionClientException e) {
            // Expected exception
            assertTrue(e.getMessage().contains("Unable to AES/GCM unwrap"));
        }

        // Cleanup
        deleteObject(BUCKET, objectKey, newClient);
        originalClient.close();
        newClient.close();
    }

    /**
     * Test RSA keyring with additionalDecryptionMaterials for ReEncryptInstructionFile.
     * This test encrypts an object with RSA_KEY_PAIR_1, then uses a client with RSA_KEY_PAIR_2 as the primary key
     * but with additionalDecryptionMaterials containing RSA_KEY_PAIR_1 to re-encrypt the instruction file.
     */
    @Test
    public void testRsaKeyringReEncryptInstructionFileWithAdditionalDecryptionMaterials() {
        // Create materials descriptions
        MaterialsDescription originalMatDesc = MaterialsDescription.builder()
                .put("purpose", "original")
                .put("version", "1")
                .build();

        MaterialsDescription newMatDesc = MaterialsDescription.builder()
                .put("purpose", "rotated")
                .put("version", "2")
                .build();

        MaterialsDescription otherMatDesc = MaterialsDescription.builder()
                .put("purpose", "testing")
                .put("do not use", "just for testing multi-key")
                .build();

        // Create RSA key pairs for the test
        PartialRsaKeyPair originalKeyPair = PartialRsaKeyPair.builder()
                .publicKey(RSA_KEY_PAIR_1.getPublic())
                .privateKey(RSA_KEY_PAIR_1.getPrivate())
                .build();

        PartialRsaKeyPair newKeyPair = PartialRsaKeyPair.builder()
                .publicKey(RSA_KEY_PAIR_2.getPublic())
                .privateKey(RSA_KEY_PAIR_2.getPrivate())
                .build();

        PartialRsaKeyPair otherKeyPair = PartialRsaKeyPair.builder()
                .publicKey(RSA_KEY_PAIR_3.getPublic())
                .privateKey(RSA_KEY_PAIR_3.getPrivate())
                .build();

        // Create a map of additional decryption key materials containing the original key pair
        Map<MaterialsDescription, RawKeyMaterial<PartialRsaKeyPair>> additionalDecryptionKeyMaterial = new HashMap<>();
        additionalDecryptionKeyMaterial.put(originalMatDesc, RawKeyMaterial.<PartialRsaKeyPair>builder()
                .materialsDescription(originalMatDesc)
                .keyMaterial(originalKeyPair)
                .build());
        additionalDecryptionKeyMaterial.put(newMatDesc, RsaKeyMaterial.rsaBuilder()
                .materialsDescription(newMatDesc)
                .keyMaterial(newKeyPair)
                .build());
        additionalDecryptionKeyMaterial.put(otherMatDesc, RsaKeyMaterial.rsaBuilder()
                .materialsDescription(otherMatDesc)
                .keyMaterial(otherKeyPair)
                .build());

        // Create an RSA keyring with the first key pair and original materials description
        RsaKeyring originalKeyring = RsaKeyring.builder()
                .wrappingKeyPair(originalKeyPair)
                .materialsDescription(originalMatDesc)
                .build();

        // Create an S3 client for the original encryption
        S3Client wrappedClient = S3Client.create();
        S3EncryptionClient originalClient = S3EncryptionClient.builder()
                .keyring(originalKeyring)
                .instructionFileConfig(
                        InstructionFileConfig.builder()
                                .instructionFileClient(wrappedClient)
                                .enableInstructionFilePutObject(true)
                                .build()
                )
                .build();

        // Create a test object key and content
        final String objectKey = appendTestSuffix("rsa-re-encrypt-instruction-file-with-additional-decryption-materials");
        final String input = "Testing re-encryption of instruction file with RSA Keyring and additional decryption materials";

        // Encrypt and upload the object with the original keyring
        originalClient.putObject(
                builder -> builder.bucket(BUCKET).key(objectKey).build(),
                RequestBody.fromString(input)
        );

        // Get the original instruction file to verify its contents
        ResponseBytes<GetObjectResponse> originalInstructionFile = wrappedClient.getObjectAsBytes(
                builder -> builder.bucket(BUCKET).key(objectKey + ".instruction").build()
        );

        // Parse the original instruction file
        String originalInstructionFileContent = originalInstructionFile.asUtf8String();
        JsonNodeParser parser = JsonNodeParser.create();
        JsonNode originalInstructionFileNode = parser.parse(originalInstructionFileContent);

        String originalIv = originalInstructionFileNode.asObject().get("x-amz-iv").asString();
        String originalEncryptedDataKeyAlgorithm = originalInstructionFileNode.asObject().get("x-amz-wrap-alg").asString();
        String originalEncryptedDataKey = originalInstructionFileNode.asObject().get("x-amz-key-v2").asString();
        JsonNode originalMatDescNode = parser.parse(originalInstructionFileNode.asObject().get("x-amz-matdesc").asString());

        assertEquals("original", originalMatDescNode.asObject().get("purpose").asString());
        assertEquals("1", originalMatDescNode.asObject().get("version").asString());

        // Create a new RSA keyring with a different key pair
        RsaKeyring newKeyring = RsaKeyring.builder()
                .wrappingKeyPair(newKeyPair) // Different key pair than what was used for original encryption
                .materialsDescription(newMatDesc)
                .additionalDecryptionKeyMaterial(additionalDecryptionKeyMaterial)
                .build();

        // Create a client with the new keyring
        S3EncryptionClient newClient = S3EncryptionClient.builder()
                .keyring(newKeyring)
                .instructionFileConfig(
                        InstructionFileConfig.builder()
                                .instructionFileClient(wrappedClient)
                                .enableInstructionFilePutObject(true)
                                .build()
                )
                .build();

        // Re-encrypt the instruction file with the new keyring
        ReEncryptInstructionFileRequest reEncryptRequest = ReEncryptInstructionFileRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .newKeyring(newKeyring)
                .build();

        // The re-encryption should succeed because the new client contains the original key in additionalDecryptionMaterials
        ReEncryptInstructionFileResponse response = newClient.reEncryptInstructionFile(reEncryptRequest);

        // Verify the response
        assertEquals(BUCKET, response.bucket());
        assertEquals(objectKey, response.key());
        assertEquals("instruction", response.instructionFileSuffix());

        // Get the re-encrypted instruction file to verify its contents
        ResponseBytes<GetObjectResponse> reEncryptedInstructionFile = wrappedClient.getObjectAsBytes(
                builder -> builder.bucket(BUCKET).key(objectKey + ".instruction").build()
        );

        // Parse the re-encrypted instruction file
        String reEncryptedInstructionFileContent = reEncryptedInstructionFile.asUtf8String();
        JsonNode reEncryptedInstructionFileNode = parser.parse(reEncryptedInstructionFileContent);

        String reEncryptedIv = reEncryptedInstructionFileNode.asObject().get("x-amz-iv").asString();
        String reEncryptedDataKeyAlgorithm = reEncryptedInstructionFileNode.asObject().get("x-amz-wrap-alg").asString();
        String reEncryptedDataKey = reEncryptedInstructionFileNode.asObject().get("x-amz-key-v2").asString();
        JsonNode reEncryptedMatDescNode = parser.parse(reEncryptedInstructionFileNode.asObject().get("x-amz-matdesc").asString());

        // Verify the re-encrypted instruction file has the new materials description
        assertEquals("rotated", reEncryptedMatDescNode.asObject().get("purpose").asString());
        assertEquals("2", reEncryptedMatDescNode.asObject().get("version").asString());

        // Verify the IV is preserved but the encrypted data key is different
        assertEquals(originalIv, reEncryptedIv);
        assertEquals(originalEncryptedDataKeyAlgorithm, reEncryptedDataKeyAlgorithm);
        assertNotEquals(originalEncryptedDataKey, reEncryptedDataKey);

        // Verify decryption works with the new client (already created above)

        // Verify the object can be decrypted with the new key
        ResponseBytes<GetObjectResponse> decryptedObject = newClient.getObjectAsBytes(
                GetObjectRequest.builder().bucket(BUCKET).key(objectKey).build()
        );
        assertEquals(input, decryptedObject.asUtf8String());

        // Verify the original client can no longer decrypt the object with the original keyring
        try {
            originalClient.getObjectAsBytes(
                    GetObjectRequest.builder().bucket(BUCKET).key(objectKey).build()
            );
            assertTrue(false, "Original client should not be able to decrypt the re-encrypted object");
        } catch (S3EncryptionClientException e) {
            // Expected exception
            assertTrue(e.getMessage().contains("Unable to RSA-OAEP-SHA1 unwrap"));
        }

        // Cleanup
        deleteObject(BUCKET, objectKey, newClient);
        originalClient.close();
        newClient.close();
    }

    /**
     * Test RSA keyring with custom suffix and additionalDecryptionMaterials for ReEncryptInstructionFile.
     * This test encrypts an object with RSA_KEY_PAIR_1, then uses a client with RSA_KEY_PAIR_2 as the primary key
     * but with additionalDecryptionMaterials containing RSA_KEY_PAIR_1 to re-encrypt the instruction file with a custom suffix.
     */
    @Test
    public void testRsaKeyringReEncryptInstructionFileWithCustomSuffixAndAdditionalDecryptionMaterials() {
        // Create materials descriptions
        MaterialsDescription originalMatDesc = MaterialsDescription.builder()
                .put("purpose", "original")
                .put("access", "owner")
                .build();

        MaterialsDescription newMatDesc = MaterialsDescription.builder()
                .put("purpose", "shared")
                .put("access", "partner")
                .build();

        MaterialsDescription otherMatDesc = MaterialsDescription.builder()
                .put("purpose", "testing")
                .put("do not use", "just for testing multi-key")
                .build();

        // Create RSA key pairs for the test
        PartialRsaKeyPair originalKeyPair = PartialRsaKeyPair.builder()
                .publicKey(RSA_KEY_PAIR_1.getPublic())
                .privateKey(RSA_KEY_PAIR_1.getPrivate())
                .build();

        PartialRsaKeyPair newKeyPair = PartialRsaKeyPair.builder()
                .publicKey(RSA_KEY_PAIR_2.getPublic())
                .privateKey(RSA_KEY_PAIR_2.getPrivate())
                .build();

        PartialRsaKeyPair otherKeyPair = PartialRsaKeyPair.builder()
                .publicKey(RSA_KEY_PAIR_3.getPublic())
                .privateKey(RSA_KEY_PAIR_3.getPrivate())
                .build();

        // Create a map of additional decryption key materials containing the original key pair
        Map<MaterialsDescription, RawKeyMaterial<PartialRsaKeyPair>> additionalDecryptionKeyMaterial = new HashMap<>();
        additionalDecryptionKeyMaterial.put(originalMatDesc, RawKeyMaterial.<PartialRsaKeyPair>builder()
                .materialsDescription(originalMatDesc)
                .keyMaterial(originalKeyPair)
                .build());
        additionalDecryptionKeyMaterial.put(newMatDesc, RsaKeyMaterial.rsaBuilder()
                .materialsDescription(newMatDesc)
                .keyMaterial(newKeyPair)
                .build());
        additionalDecryptionKeyMaterial.put(otherMatDesc, RsaKeyMaterial.rsaBuilder()
                .materialsDescription(otherMatDesc)
                .keyMaterial(otherKeyPair)
                .build());

        // Create an RSA keyring with the first key pair and original materials description
        RsaKeyring originalKeyring = RsaKeyring.builder()
                .wrappingKeyPair(originalKeyPair)
                .materialsDescription(originalMatDesc)
                .build();

        // Create an S3 client for the original encryption
        S3Client wrappedClient = S3Client.create();
        S3EncryptionClient originalClient = S3EncryptionClient.builder()
                .keyring(originalKeyring)
                .instructionFileConfig(
                        InstructionFileConfig.builder()
                                .instructionFileClient(wrappedClient)
                                .enableInstructionFilePutObject(true)
                                .build()
                )
                .build();

        // Create a test object key and content
        final String objectKey = appendTestSuffix("rsa-re-encrypt-instruction-file-with-custom-suffix-and-additional-decryption-materials");
        final String input = "Testing re-encryption of instruction file with RSA Keyring, custom suffix, and additional decryption materials";
        final String customSuffix = "partner-access";

        // Encrypt and upload the object with the original keyring
        originalClient.putObject(
                builder -> builder.bucket(BUCKET).key(objectKey).build(),
                RequestBody.fromString(input)
        );

        // Get the original instruction file to verify its contents
        ResponseBytes<GetObjectResponse> originalInstructionFile = wrappedClient.getObjectAsBytes(
                builder -> builder.bucket(BUCKET).key(objectKey + ".instruction").build()
        );

        // Parse the original instruction file
        String originalInstructionFileContent = originalInstructionFile.asUtf8String();
        JsonNodeParser parser = JsonNodeParser.create();
        JsonNode originalInstructionFileNode = parser.parse(originalInstructionFileContent);

        String originalIv = originalInstructionFileNode.asObject().get("x-amz-iv").asString();
        String originalEncryptedDataKeyAlgorithm = originalInstructionFileNode.asObject().get("x-amz-wrap-alg").asString();
        String originalEncryptedDataKey = originalInstructionFileNode.asObject().get("x-amz-key-v2").asString();
        JsonNode originalMatDescNode = parser.parse(originalInstructionFileNode.asObject().get("x-amz-matdesc").asString());

        assertEquals("original", originalMatDescNode.asObject().get("purpose").asString());
        assertEquals("owner", originalMatDescNode.asObject().get("access").asString());

        // Create a new RSA keyring with a different key pair
        RsaKeyring newKeyring = RsaKeyring.builder()
                .wrappingKeyPair(newKeyPair) // Different key pair than what was used for original encryption
                .materialsDescription(newMatDesc)
                .additionalDecryptionKeyMaterial(additionalDecryptionKeyMaterial)
                .build();

        // Create a client with the new keyring
        S3EncryptionClient newClient = S3EncryptionClient.builder()
                .keyring(newKeyring)
                .instructionFileConfig(
                        InstructionFileConfig.builder()
                                .instructionFileClient(wrappedClient)
                                .enableInstructionFilePutObject(true)
                                .build()
                )
                .build();

        // Re-encrypt the instruction file with the new keyring and custom suffix
        ReEncryptInstructionFileRequest reEncryptRequest = ReEncryptInstructionFileRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .newKeyring(newKeyring)
                .instructionFileSuffix(customSuffix)
                .build();

        // The re-encryption should succeed because the new client contains the original key in additionalDecryptionMaterials
        ReEncryptInstructionFileResponse response = newClient.reEncryptInstructionFile(reEncryptRequest);

        // Verify the response
        assertEquals(BUCKET, response.bucket());
        assertEquals(objectKey, response.key());
        assertEquals(customSuffix, response.instructionFileSuffix());

        // Get the re-encrypted instruction file with custom suffix to verify its contents
        ResponseBytes<GetObjectResponse> reEncryptedInstructionFile = wrappedClient.getObjectAsBytes(
                builder -> builder.bucket(BUCKET).key(objectKey + "." + customSuffix).build()
        );

        // Parse the re-encrypted instruction file
        String reEncryptedInstructionFileContent = reEncryptedInstructionFile.asUtf8String();
        JsonNode reEncryptedInstructionFileNode = parser.parse(reEncryptedInstructionFileContent);

        String reEncryptedIv = reEncryptedInstructionFileNode.asObject().get("x-amz-iv").asString();
        String reEncryptedDataKeyAlgorithm = reEncryptedInstructionFileNode.asObject().get("x-amz-wrap-alg").asString();
        String reEncryptedDataKey = reEncryptedInstructionFileNode.asObject().get("x-amz-key-v2").asString();
        JsonNode reEncryptedMatDescNode = parser.parse(reEncryptedInstructionFileNode.asObject().get("x-amz-matdesc").asString());

        // Verify the re-encrypted instruction file has the new materials description
        assertEquals("shared", reEncryptedMatDescNode.asObject().get("purpose").asString());
        assertEquals("partner", reEncryptedMatDescNode.asObject().get("access").asString());

        // Verify the IV is preserved but the encrypted data key is different
        assertEquals(originalIv, reEncryptedIv);
        assertEquals(originalEncryptedDataKeyAlgorithm, reEncryptedDataKeyAlgorithm);
        assertNotEquals(originalEncryptedDataKey, reEncryptedDataKey);

        // Verify decryption works with the new client (already created above)

        // Verify the object can be decrypted with the new key and custom suffix
        ResponseBytes<GetObjectResponse> decryptedObject = newClient.getObjectAsBytes(
                GetObjectRequest.builder()
                        .bucket(BUCKET)
                        .key(objectKey)
                        .overrideConfiguration(withCustomInstructionFileSuffix("." + customSuffix))
                        .build()
        );
        assertEquals(input, decryptedObject.asUtf8String());

        // Verify the original client can still decrypt using the default instruction file
        ResponseBytes<GetObjectResponse> originalDecryptedObject = originalClient.getObjectAsBytes(
                GetObjectRequest.builder().bucket(BUCKET).key(objectKey).build()
        );
        assertEquals(input, originalDecryptedObject.asUtf8String());

        // Cleanup
        deleteObject(BUCKET, objectKey, newClient);
        originalClient.close();
        newClient.close();
    }
}
