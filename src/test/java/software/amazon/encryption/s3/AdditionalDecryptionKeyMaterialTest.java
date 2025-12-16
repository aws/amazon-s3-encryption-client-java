// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.MaterialsDescription;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;
import software.amazon.encryption.s3.materials.RawKeyMaterial;
import software.amazon.encryption.s3.materials.RsaKeyring;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

/**
 * This class is an integration test for verifying the additionalDecryptionKeyMaterial feature
 * in the S3EncryptionClient.
 */
public class AdditionalDecryptionKeyMaterialTest {

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
     * Test AES keyring with null additionalDecryptionKeyMaterial map.
     * This tests the default behavior when no additional key material is provided.
     */
    @Test
    public void testAesKeyringWithNullAdditionalKeyMaterial() {
        final String objectKey = appendTestSuffix("aes-null-additional-key-material");
        final String input = "AES with null additional key material";

        // Create a materials description for the encryption
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create an AES keyring with the first key and materials description
        AesKeyring encryptionKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_1)
                .materialsDescription(materialsDescription)
                .build();

        // Create an S3 encryption client for encryption
        S3Client encryptionClient = S3EncryptionClient.builder()
                .keyring(encryptionKeyring)
                .build();

        // Encrypt and upload the object
        encryptionClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Create an AES keyring with the same key but null additionalDecryptionKeyMaterial
        AesKeyring decryptionKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_1)
                .materialsDescription(materialsDescription)
                .additionalDecryptionKeyMaterial(null) // Explicitly set to null
                .build();

        // Create an S3 encryption client for decryption
        S3Client decryptionClient = S3EncryptionClient.builder()
                .keyring(decryptionKeyring)
                .build();

        // Decrypt the object
        ResponseBytes<GetObjectResponse> objectResponse = decryptionClient.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Verify the decrypted content
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, decryptionClient);
        encryptionClient.close();
        decryptionClient.close();
    }

    /**
     * Test AES keyring with empty additionalDecryptionKeyMaterial map.
     * This tests the behavior when an empty map is provided.
     */
    @Test
    public void testAesKeyringWithEmptyAdditionalKeyMaterial() {
        final String objectKey = appendTestSuffix("aes-empty-additional-key-material");
        final String input = "AES with empty additional key material";

        // Create a materials description for the encryption
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create an AES keyring with the first key and materials description
        AesKeyring encryptionKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_1)
                .materialsDescription(materialsDescription)
                .build();

        // Create an S3 encryption client for encryption
        S3Client encryptionClient = S3EncryptionClient.builder()
                .keyring(encryptionKeyring)
                .build();

        // Encrypt and upload the object
        encryptionClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Create an AES keyring with the same key but empty additionalDecryptionKeyMaterial
        Map<MaterialsDescription, RawKeyMaterial<SecretKey>> emptyMap = new HashMap<>();
        AesKeyring decryptionKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_1)
                .materialsDescription(materialsDescription)
                .additionalDecryptionKeyMaterial(emptyMap) // Empty map
                .build();

        // Create an S3 encryption client for decryption
        S3Client decryptionClient = S3EncryptionClient.builder()
                .keyring(decryptionKeyring)
                .build();

        // Decrypt the object
        ResponseBytes<GetObjectResponse> objectResponse = decryptionClient.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Verify the decrypted content
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, decryptionClient);
        encryptionClient.close();
        decryptionClient.close();
    }

    /**
     * Test AES keyring with a singleton additionalDecryptionKeyMaterial map.
     * This tests the behavior when a single additional key material is provided.
     */
    @Test
    public void testAesKeyringWithSingletonAdditionalKeyMaterial() {
        final String objectKey = appendTestSuffix("aes-singleton-additional-key-material");
        final String input = "AES with singleton additional key material";

        // Create a materials description for the encryption
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create an AES keyring with the first key and materials description
        AesKeyring encryptionKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_1)
                .materialsDescription(materialsDescription)
                .build();

        // Create an S3 encryption client for encryption
        S3Client encryptionClient = S3EncryptionClient.builder()
                .keyring(encryptionKeyring)
                .build();

        // Encrypt and upload the object
        encryptionClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Create a singleton map with the matching materials description and the same key used for encryption
        Map<MaterialsDescription, RawKeyMaterial<SecretKey>> singletonMap = new HashMap<>();
        singletonMap.put(materialsDescription, RawKeyMaterial.<SecretKey>builder()
                .materialsDescription(materialsDescription)
                .keyMaterial(AES_KEY_1) // Use the same key that was used for encryption
                .build());

        // Create an AES keyring with a different key but with additionalDecryptionKeyMaterial containing the original key
        AesKeyring decryptionKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_3) // Different key than what was used for encryption
                .materialsDescription(MaterialsDescription.builder().put("different", "description").build())
                .additionalDecryptionKeyMaterial(singletonMap) // Contains the key that matches the materials description
                .build();

        // Create an S3 encryption client for decryption
        S3Client decryptionClient = S3EncryptionClient.builder()
                .keyring(decryptionKeyring)
                .build();

        // Decrypt the object
        ResponseBytes<GetObjectResponse> objectResponse = decryptionClient.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Verify the decrypted content
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, decryptionClient);
        encryptionClient.close();
        decryptionClient.close();
    }

    /**
     * Test AES keyring with multiple entries in the additionalDecryptionKeyMaterial map.
     * This tests the behavior when multiple additional key materials are provided.
     */
    @Test
    public void testAesKeyringWithMultipleAdditionalKeyMaterials() {
        final String objectKey = appendTestSuffix("aes-multiple-additional-key-materials");
        final String input = "AES with multiple additional key materials";

        // Create a materials description for the encryption
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create an AES keyring with the first key and materials description
        AesKeyring encryptionKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_1)
                .materialsDescription(materialsDescription)
                .build();

        // Create an S3 encryption client for encryption
        S3Client encryptionClient = S3EncryptionClient.builder()
                .keyring(encryptionKeyring)
                .build();

        // Encrypt and upload the object
        encryptionClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Create a map with multiple entries
        Map<MaterialsDescription, RawKeyMaterial<SecretKey>> multipleMap = new HashMap<>();

        // Add an entry that doesn't match
        MaterialsDescription nonMatchingDesc = MaterialsDescription.builder()
                .put("purpose", "different")
                .put("version", "2")
                .build();
        multipleMap.put(nonMatchingDesc, RawKeyMaterial.<SecretKey>builder()
                .materialsDescription(nonMatchingDesc)
                .keyMaterial(AES_KEY_2)
                .build());

        // Add the matching entry
        multipleMap.put(materialsDescription, RawKeyMaterial.<SecretKey>builder()
                .materialsDescription(materialsDescription)
                .keyMaterial(AES_KEY_1)
                .build());

        // Create an AES keyring with a different key but with additionalDecryptionKeyMaterial containing the original key
        AesKeyring decryptionKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_3) // Different key than what was used for encryption
                .materialsDescription(MaterialsDescription.builder().put("different", "description").build())
                .additionalDecryptionKeyMaterial(multipleMap) // Contains the key that matches the materials description
                .build();

        // Create an S3 encryption client for decryption
        S3Client decryptionClient = S3EncryptionClient.builder()
                .keyring(decryptionKeyring)
                .build();

        // Decrypt the object
        ResponseBytes<GetObjectResponse> objectResponse = decryptionClient.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Verify the decrypted content
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, decryptionClient);
        encryptionClient.close();
        decryptionClient.close();
    }

    /**
     * Test AES keyring with additionalDecryptionKeyMaterial that doesn't match.
     * This tests the behavior when no matching key material is found and it should fall back to the default key.
     */
    @Test
    public void testAesKeyringWithNonMatchingAdditionalKeyMaterial() {
        final String objectKey = appendTestSuffix("aes-non-matching-additional-key-material");
        final String input = "AES with non-matching additional key material";

        // Create a materials description for the encryption
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create an AES keyring with the first key and materials description
        AesKeyring encryptionKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_1)
                .materialsDescription(materialsDescription)
                .build();

        // Create an S3 encryption client for encryption
        S3Client encryptionClient = S3EncryptionClient.builder()
                .keyring(encryptionKeyring)
                .build();

        // Encrypt and upload the object
        encryptionClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Create a map with a non-matching entry
        Map<MaterialsDescription, RawKeyMaterial<SecretKey>> nonMatchingMap = new HashMap<>();
        MaterialsDescription nonMatchingDesc = MaterialsDescription.builder()
                .put("purpose", "different")
                .put("version", "2")
                .build();
        nonMatchingMap.put(nonMatchingDesc, RawKeyMaterial.<SecretKey>builder()
                .materialsDescription(nonMatchingDesc)
                .keyMaterial(AES_KEY_2)
                .build());

        // Create an AES keyring with the correct key as the default but with non-matching additionalDecryptionKeyMaterial
        AesKeyring decryptionKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_1) // Same key as used for encryption
                .materialsDescription(materialsDescription)
                .additionalDecryptionKeyMaterial(nonMatchingMap) // Contains a key that doesn't match
                .build();

        // Create an S3 encryption client for decryption
        S3Client decryptionClient = S3EncryptionClient.builder()
                .keyring(decryptionKeyring)
                .build();

        // Decrypt the object
        ResponseBytes<GetObjectResponse> objectResponse = decryptionClient.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Verify the decrypted content
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, decryptionClient);
        encryptionClient.close();
        decryptionClient.close();
    }

    /**
     * Test AES keyring with additionalDecryptionKeyMaterial that doesn't match and a wrong default key.
     * This tests the behavior when no matching key material is found and the default key is also wrong.
     */
    @Test
    public void testAesKeyringWithNonMatchingAdditionalKeyMaterialAndWrongDefaultKey() {
        final String objectKey = appendTestSuffix("aes-non-matching-additional-key-material-wrong-default");
        final String input = "AES with non-matching additional key material and wrong default key";

        // Create a materials description for the encryption
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create an AES keyring with the first key and materials description
        AesKeyring encryptionKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_1)
                .materialsDescription(materialsDescription)
                .build();

        // Create an S3 encryption client for encryption
        S3Client encryptionClient = S3EncryptionClient.builder()
                .keyring(encryptionKeyring)
                .build();

        // Encrypt and upload the object
        encryptionClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Create a map with a non-matching entry
        Map<MaterialsDescription, RawKeyMaterial<SecretKey>> nonMatchingMap = new HashMap<>();
        MaterialsDescription nonMatchingDesc = MaterialsDescription.builder()
                .put("purpose", "different")
                .put("version", "2")
                .build();
        nonMatchingMap.put(nonMatchingDesc, RawKeyMaterial.<SecretKey>builder()
                .materialsDescription(nonMatchingDesc)
                .keyMaterial(AES_KEY_2)
                .build());

        // Create an AES keyring with a wrong default key and non-matching additionalDecryptionKeyMaterial
        AesKeyring decryptionKeyring = AesKeyring.builder()
                .wrappingKey(AES_KEY_3) // Different key than what was used for encryption
                .materialsDescription(materialsDescription)
                .additionalDecryptionKeyMaterial(nonMatchingMap) // Contains a key that doesn't match
                .build();

        // Create an S3 encryption client for decryption
        S3Client decryptionClient = S3EncryptionClient.builder()
                .keyring(decryptionKeyring)
                .build();

        // Attempt to decrypt the object, which should fail
        assertThrows(S3EncryptionClientException.class, () -> decryptionClient.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build()));

        // Cleanup
        deleteObject(BUCKET, objectKey, decryptionClient);
        encryptionClient.close();
        decryptionClient.close();
    }

    /**
     * Test RSA keyring with null additionalDecryptionKeyMaterial map.
     * This tests the default behavior when no additional key material is provided.
     */
    @Test
    public void testRsaKeyringWithNullAdditionalKeyMaterial() {
        final String objectKey = appendTestSuffix("rsa-null-additional-key-material");
        final String input = "RSA with null additional key material";

        // Create a materials description for the encryption
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create an RSA keyring with the first key pair and materials description
        RsaKeyring encryptionKeyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_1.getPublic())
                        .privateKey(RSA_KEY_PAIR_1.getPrivate())
                        .build())
                .materialsDescription(materialsDescription)
                .build();

        // Create an S3 encryption client for encryption
        S3Client encryptionClient = S3EncryptionClient.builder()
                .keyring(encryptionKeyring)
                .build();

        // Encrypt and upload the object
        encryptionClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Create an RSA keyring with the same key pair but null additionalDecryptionKeyMaterial
        RsaKeyring decryptionKeyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_1.getPublic())
                        .privateKey(RSA_KEY_PAIR_1.getPrivate())
                        .build())
                .materialsDescription(materialsDescription)
                .additionalDecryptionKeyMaterial(null) // Explicitly set to null
                .build();

        // Create an S3 encryption client for decryption
        S3Client decryptionClient = S3EncryptionClient.builder()
                .keyring(decryptionKeyring)
                .build();

        // Decrypt the object
        ResponseBytes<GetObjectResponse> objectResponse = decryptionClient.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Verify the decrypted content
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, decryptionClient);
        encryptionClient.close();
        decryptionClient.close();
    }

    /**
     * Test RSA keyring with empty additionalDecryptionKeyMaterial map.
     * This tests the behavior when an empty map is provided.
     */
    @Test
    public void testRsaKeyringWithEmptyAdditionalKeyMaterial() {
        final String objectKey = appendTestSuffix("rsa-empty-additional-key-material");
        final String input = "RSA with empty additional key material";

        // Create a materials description for the encryption
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create an RSA keyring with the first key pair and materials description
        RsaKeyring encryptionKeyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_1.getPublic())
                        .privateKey(RSA_KEY_PAIR_1.getPrivate())
                        .build())
                .materialsDescription(materialsDescription)
                .build();

        // Create an S3 encryption client for encryption
        S3Client encryptionClient = S3EncryptionClient.builder()
                .keyring(encryptionKeyring)
                .build();

        // Encrypt and upload the object
        encryptionClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Create an RSA keyring with the same key pair but empty additionalDecryptionKeyMaterial
        Map<MaterialsDescription, RawKeyMaterial<PartialRsaKeyPair>> emptyMap = new HashMap<>();
        RsaKeyring decryptionKeyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_1.getPublic())
                        .privateKey(RSA_KEY_PAIR_1.getPrivate())
                        .build())
                .materialsDescription(materialsDescription)
                .additionalDecryptionKeyMaterial(emptyMap) // Empty map
                .build();

        // Create an S3 encryption client for decryption
        S3Client decryptionClient = S3EncryptionClient.builder()
                .keyring(decryptionKeyring)
                .build();

        // Decrypt the object
        ResponseBytes<GetObjectResponse> objectResponse = decryptionClient.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Verify the decrypted content
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, decryptionClient);
        encryptionClient.close();
        decryptionClient.close();
    }

    /**
     * Test RSA keyring with a singleton additionalDecryptionKeyMaterial map.
     * This tests the behavior when a single additional key material is provided.
     */
    @Test
    public void testRsaKeyringWithSingletonAdditionalKeyMaterial() {
        final String objectKey = appendTestSuffix("rsa-singleton-additional-key-material");
        final String input = "RSA with singleton additional key material";

        // Create a materials description for the encryption
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create an RSA keyring with the first key pair and materials description
        RsaKeyring encryptionKeyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_1.getPublic())
                        .privateKey(RSA_KEY_PAIR_1.getPrivate())
                        .build())
                .materialsDescription(materialsDescription)
                .build();

        // Create an S3 encryption client for encryption
        S3Client encryptionClient = S3EncryptionClient.builder()
                .keyring(encryptionKeyring)
                .build();

        // Encrypt and upload the object
        encryptionClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Create a singleton map with the matching materials description and the same key pair used for encryption
        Map<MaterialsDescription, RawKeyMaterial<PartialRsaKeyPair>> singletonMap = new HashMap<>();
        singletonMap.put(materialsDescription, RawKeyMaterial.<PartialRsaKeyPair>builder()
                .materialsDescription(materialsDescription)
                .keyMaterial(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_1.getPublic())
                        .privateKey(RSA_KEY_PAIR_1.getPrivate())
                        .build())
                .build());

        // Create an RSA keyring with a different key pair but with additionalDecryptionKeyMaterial containing the original key pair
        RsaKeyring decryptionKeyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_3.getPublic())
                        .privateKey(RSA_KEY_PAIR_3.getPrivate())
                        .build())
                .materialsDescription(MaterialsDescription.builder().put("different", "description").build())
                .additionalDecryptionKeyMaterial(singletonMap) // Contains the key pair that matches the materials description
                .build();

        // Create an S3 encryption client for decryption
        S3Client decryptionClient = S3EncryptionClient.builder()
                .keyring(decryptionKeyring)
                .build();

        // Decrypt the object
        ResponseBytes<GetObjectResponse> objectResponse = decryptionClient.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Verify the decrypted content
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, decryptionClient);
        encryptionClient.close();
        decryptionClient.close();
    }

    /**
     * Test RSA keyring with multiple entries in the additionalDecryptionKeyMaterial map.
     * This tests the behavior when multiple additional key materials are provided.
     */
    @Test
    public void testRsaKeyringWithMultipleAdditionalKeyMaterials() {
        final String objectKey = appendTestSuffix("rsa-multiple-additional-key-materials");
        final String input = "RSA with multiple additional key materials";

        // Create a materials description for the encryption
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create an RSA keyring with the first key pair and materials description
        RsaKeyring encryptionKeyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_1.getPublic())
                        .privateKey(RSA_KEY_PAIR_1.getPrivate())
                        .build())
                .materialsDescription(materialsDescription)
                .build();

        // Create an S3 encryption client for encryption
        S3Client encryptionClient = S3EncryptionClient.builder()
                .keyring(encryptionKeyring)
                .build();

        // Encrypt and upload the object
        encryptionClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Create a map with multiple entries
        Map<MaterialsDescription, RawKeyMaterial<PartialRsaKeyPair>> multipleMap = new HashMap<>();

        // Add an entry that doesn't match
        MaterialsDescription nonMatchingDesc = MaterialsDescription.builder()
                .put("purpose", "different")
                .put("version", "2")
                .build();
        multipleMap.put(nonMatchingDesc, RawKeyMaterial.<PartialRsaKeyPair>builder()
                .materialsDescription(nonMatchingDesc)
                .keyMaterial(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_2.getPublic())
                        .privateKey(RSA_KEY_PAIR_2.getPrivate())
                        .build())
                .build());

        // Add the matching entry
        multipleMap.put(materialsDescription, RawKeyMaterial.<PartialRsaKeyPair>builder()
                .materialsDescription(materialsDescription)
                .keyMaterial(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_1.getPublic())
                        .privateKey(RSA_KEY_PAIR_1.getPrivate())
                        .build())
                .build());

        // Create an RSA keyring with a different key pair but with additionalDecryptionKeyMaterial containing the original key pair
        RsaKeyring decryptionKeyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_3.getPublic())
                        .privateKey(RSA_KEY_PAIR_3.getPrivate())
                        .build())
                .materialsDescription(MaterialsDescription.builder().put("different", "description").build())
                .additionalDecryptionKeyMaterial(multipleMap) // Contains the key pair that matches the materials description
                .build();

        // Create an S3 encryption client for decryption
        S3Client decryptionClient = S3EncryptionClient.builder()
                .keyring(decryptionKeyring)
                .build();

        // Decrypt the object
        ResponseBytes<GetObjectResponse> objectResponse = decryptionClient.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Verify the decrypted content
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, decryptionClient);
        encryptionClient.close();
        decryptionClient.close();
    }

    /**
     * Test RSA keyring with additionalDecryptionKeyMaterial that doesn't match.
     * This tests the behavior when no matching key material is found and it should fall back to the default key.
     */
    @Test
    public void testRsaKeyringWithNonMatchingAdditionalKeyMaterial() {
        final String objectKey = appendTestSuffix("rsa-non-matching-additional-key-material");
        final String input = "RSA with non-matching additional key material";

        // Create a materials description for the encryption
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create an RSA keyring with the first key pair and materials description
        RsaKeyring encryptionKeyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_1.getPublic())
                        .privateKey(RSA_KEY_PAIR_1.getPrivate())
                        .build())
                .materialsDescription(materialsDescription)
                .build();

        // Create an S3 encryption client for encryption
        S3Client encryptionClient = S3EncryptionClient.builder()
                .keyring(encryptionKeyring)
                .build();

        // Encrypt and upload the object
        encryptionClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Create a map with a non-matching entry
        Map<MaterialsDescription, RawKeyMaterial<PartialRsaKeyPair>> nonMatchingMap = new HashMap<>();
        MaterialsDescription nonMatchingDesc = MaterialsDescription.builder()
                .put("purpose", "different")
                .put("version", "2")
                .build();
        nonMatchingMap.put(nonMatchingDesc, RawKeyMaterial.<PartialRsaKeyPair>builder()
                .materialsDescription(nonMatchingDesc)
                .keyMaterial(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_2.getPublic())
                        .privateKey(RSA_KEY_PAIR_2.getPrivate())
                        .build())
                .build());

        // Create an RSA keyring with the correct key pair as the default but with non-matching additionalDecryptionKeyMaterial
        RsaKeyring decryptionKeyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_1.getPublic())
                        .privateKey(RSA_KEY_PAIR_1.getPrivate())
                        .build())
                .materialsDescription(materialsDescription)
                .additionalDecryptionKeyMaterial(nonMatchingMap) // Contains a key pair that doesn't match
                .build();

        // Create an S3 encryption client for decryption
        S3Client decryptionClient = S3EncryptionClient.builder()
                .keyring(decryptionKeyring)
                .build();

        // Decrypt the object
        ResponseBytes<GetObjectResponse> objectResponse = decryptionClient.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        // Verify the decrypted content
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, decryptionClient);
        encryptionClient.close();
        decryptionClient.close();
    }

    /**
     * Test RSA keyring with additionalDecryptionKeyMaterial that doesn't match and a wrong default key.
     * This tests the behavior when no matching key material is found and the default key is also wrong.
     */
    @Test
    public void testRsaKeyringWithNonMatchingAdditionalKeyMaterialAndWrongDefaultKey() {
        final String objectKey = appendTestSuffix("rsa-non-matching-additional-key-material-wrong-default");
        final String input = "RSA with non-matching additional key material and wrong default key";

        // Create a materials description for the encryption
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create an RSA keyring with the first key pair and materials description
        RsaKeyring encryptionKeyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_1.getPublic())
                        .privateKey(RSA_KEY_PAIR_1.getPrivate())
                        .build())
                .materialsDescription(materialsDescription)
                .build();

        // Create an S3 encryption client for encryption
        S3Client encryptionClient = S3EncryptionClient.builder()
                .keyring(encryptionKeyring)
                .build();

        // Encrypt and upload the object
        encryptionClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Create a map with a non-matching entry
        Map<MaterialsDescription, RawKeyMaterial<PartialRsaKeyPair>> nonMatchingMap = new HashMap<>();
        MaterialsDescription nonMatchingDesc = MaterialsDescription.builder()
                .put("purpose", "different")
                .put("version", "2")
                .build();
        nonMatchingMap.put(nonMatchingDesc, RawKeyMaterial.<PartialRsaKeyPair>builder()
                .materialsDescription(nonMatchingDesc)
                .keyMaterial(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_2.getPublic())
                        .privateKey(RSA_KEY_PAIR_2.getPrivate())
                        .build())
                .build());

        // Create an RSA keyring with a wrong default key pair and non-matching additionalDecryptionKeyMaterial
        RsaKeyring decryptionKeyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR_3.getPublic())
                        .privateKey(RSA_KEY_PAIR_3.getPrivate())
                        .build())
                .materialsDescription(materialsDescription)
                .additionalDecryptionKeyMaterial(nonMatchingMap) // Contains a key pair that doesn't match
                .build();

        // Create an S3 encryption client for decryption
        S3Client decryptionClient = S3EncryptionClient.builder()
                .keyring(decryptionKeyring)
                .build();

        // Attempt to decrypt the object, which should fail
        assertThrows(S3EncryptionClientException.class, () -> decryptionClient.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build()));

        // Cleanup
        deleteObject(BUCKET, objectKey, decryptionClient);
        encryptionClient.close();
        decryptionClient.close();
    }
}
