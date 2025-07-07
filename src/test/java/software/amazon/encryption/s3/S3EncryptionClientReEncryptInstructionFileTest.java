// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import com.amazonaws.AmazonClientException;
import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoConfigurationV2;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import com.amazonaws.services.s3.model.EncryptedGetObjectRequest;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.apache.commons.io.IOUtils;
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
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.MaterialsDescription;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;
import software.amazon.encryption.s3.materials.RsaKeyring;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.S3EncryptionClient.withCustomInstructionFileSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class S3EncryptionClientReEncryptInstructionFileTest {
  private static SecretKey AES_KEY;
  private static SecretKey AES_KEY_TWO;
  private static KeyPair RSA_KEY_PAIR;
  private static KeyPair THIRD_PARTY_RSA_KEY_PAIR;

  @BeforeAll
  public static void setUp() throws NoSuchAlgorithmException {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(256);
    AES_KEY = keyGen.generateKey();
    AES_KEY_TWO = keyGen.generateKey();

    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(2048);
    RSA_KEY_PAIR = keyPairGen.generateKeyPair();
    THIRD_PARTY_RSA_KEY_PAIR = keyPairGen.generateKeyPair();
  }

  @Test
  public void testAesReEncryptInstructionFileFailsWithSameMaterialsDescription() {
    AesKeyring oldKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("rotated", "no")
        .build())
      .build();

    S3Client wrappedClient = S3Client.create();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(oldKeyring)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    final String objectKey = appendTestSuffix("aes-re-encrypt-instruction-file-test");
    final String input = "Testing re-encryption of instruction file with AES Keyring";

    client.putObject(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build(), RequestBody.fromString(input));

    AesKeyring newKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY_TWO)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("rotated", "no")
        .build())
      .build();

    ReEncryptInstructionFileRequest reEncryptInstructionFileRequest = ReEncryptInstructionFileRequest.builder()
      .bucket(BUCKET)
      .key(objectKey)
      .newKeyring(newKeyring)
      .build();

   try {
     client.reEncryptInstructionFile(reEncryptInstructionFileRequest);
     throw new RuntimeException("Expected failure");
   } catch (S3EncryptionClientException e) {;
     assertTrue(e.getMessage().contains("New keyring must have new materials description!"));
   }

    deleteObject(BUCKET, objectKey, client);
  }

  @Test
  public void testRsaReEncryptInstructionFileFailsWithSameMaterialsDescription() {
    PublicKey clientPublicKey = RSA_KEY_PAIR.getPublic();
    PrivateKey clientPrivateKey = RSA_KEY_PAIR.getPrivate();

    PartialRsaKeyPair clientPartialRsaKeyPair = PartialRsaKeyPair.builder()
      .publicKey(clientPublicKey)
      .privateKey(clientPrivateKey)
      .build();

    RsaKeyring clientKeyring = RsaKeyring.builder()
      .wrappingKeyPair(clientPartialRsaKeyPair)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("isOwner", "yes")
        .put("access-level", "admin")
        .build())
      .build();

    S3Client wrappedClient = S3Client.create();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(clientKeyring)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    final String objectKey = appendTestSuffix("rsa-re-encrypt-instruction-file-test");
    final String input = "Testing re-encryption of instruction file with RSA Keyring";

    client.putObject(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build(), RequestBody.fromString(input));

    PublicKey thirdPartyPublicKey = THIRD_PARTY_RSA_KEY_PAIR.getPublic();
    PrivateKey thirdPartyPrivateKey = THIRD_PARTY_RSA_KEY_PAIR.getPrivate();

    PartialRsaKeyPair thirdPartyPartialRsaKeyPair = PartialRsaKeyPair.builder()
      .publicKey(thirdPartyPublicKey)
      .privateKey(thirdPartyPrivateKey)
      .build();

    RsaKeyring thirdPartyKeyring = RsaKeyring.builder()
      .wrappingKeyPair(thirdPartyPartialRsaKeyPair)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("isOwner", "yes")
        .put("access-level", "admin")
        .build())
      .build();

    ReEncryptInstructionFileRequest reEncryptInstructionFileRequest = ReEncryptInstructionFileRequest.builder()
      .bucket(BUCKET)
      .key(objectKey)
      .instructionFileSuffix("third-party-access-instruction-file")
      .newKeyring(thirdPartyKeyring)
      .build();

    try {
      client.reEncryptInstructionFile(reEncryptInstructionFileRequest);
      throw new RuntimeException("Expected failure");
    } catch (S3EncryptionClientException e) {
      assertTrue(e.getMessage().contains("New keyring must have new materials description!"));
    }

    deleteObject(BUCKET, objectKey, client);
  }

  @Test
  public void testReEncryptInstructionFileRejectsAesKeyringWithCustomSuffix() {
    AesKeyring oldKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("rotated", "no")
        .build())
      .build();

    S3Client wrappedClient = S3Client.create();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(oldKeyring)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    final String objectKey = appendTestSuffix("aes-re-encrypt-instruction-file-test");
    final String input = "Testing re-encryption of instruction file with AES Keyring";

    client.putObject(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build(), RequestBody.fromString(input));

    AesKeyring newKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY_TWO)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("rotated", "yes")
        .build())
      .build();

    try {
      ReEncryptInstructionFileRequest reEncryptInstructionFileRequest = ReEncryptInstructionFileRequest.builder()
        .bucket(BUCKET)
        .key(objectKey)
        .newKeyring(newKeyring)
        .instructionFileSuffix("custom-suffix")
        .build();
    } catch (S3EncryptionClientException e) {
      assertTrue(e.getMessage().contains("Custom Instruction file suffix is not applicable for AES keyring!"));
    }

    deleteObject(BUCKET, objectKey, client);
  }

  @Test
  public void testReEncryptInstructionFileRejectsRsaKeyringWithDefaultSuffix() {
    PublicKey clientPublicKey = RSA_KEY_PAIR.getPublic();
    PrivateKey clientPrivateKey = RSA_KEY_PAIR.getPrivate();

    PartialRsaKeyPair clientPartialRsaKeyPair = PartialRsaKeyPair.builder()
      .publicKey(clientPublicKey)
      .privateKey(clientPrivateKey)
      .build();

    RsaKeyring clientKeyring = RsaKeyring.builder()
      .wrappingKeyPair(clientPartialRsaKeyPair)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("isOwner", "yes")
        .put("access-level", "admin")
        .build())
      .build();

    S3Client wrappedClient = S3Client.create();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(clientKeyring)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    final String objectKey = appendTestSuffix("rsa-re-encrypt-instruction-file-test");
    final String input = "Testing re-encryption of instruction file with RSA Keyring";

    client.putObject(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build(), RequestBody.fromString(input));

    PublicKey thirdPartyPublicKey = THIRD_PARTY_RSA_KEY_PAIR.getPublic();
    PrivateKey thirdPartyPrivateKey = THIRD_PARTY_RSA_KEY_PAIR.getPrivate();

    PartialRsaKeyPair thirdPartyPartialRsaKeyPair = PartialRsaKeyPair.builder()
      .publicKey(thirdPartyPublicKey)
      .privateKey(thirdPartyPrivateKey)
      .build();

    RsaKeyring thirdPartyKeyring = RsaKeyring.builder()
      .wrappingKeyPair(thirdPartyPartialRsaKeyPair)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("isOwner", "no")
        .put("access-level", "user")
        .build())
      .build();

    try {
      ReEncryptInstructionFileRequest reEncryptInstructionFileRequest = ReEncryptInstructionFileRequest.builder()
        .bucket(BUCKET)
        .key(objectKey)
        .instructionFileSuffix("instruction")
        .newKeyring(thirdPartyKeyring)
        .build();
    } catch (S3EncryptionClientException e) {
      assertTrue(e.getMessage().contains("Instruction file suffix must be different than the default one for RSA keyring!"));
    }

    deleteObject(BUCKET, objectKey, client);
  }

  @Test
  public void testAesKeyringReEncryptInstructionFile() {
    AesKeyring oldKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("rotated", "no")
        .build())
      .build();

    S3Client wrappedClient = S3Client.create();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(oldKeyring)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    final String objectKey = appendTestSuffix("aes-re-encrypt-instruction-file-test");
    final String input = "Testing re-encryption of instruction file with AES Keyring";

    client.putObject(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build(), RequestBody.fromString(input));

    ResponseBytes<GetObjectResponse> instructionFile = wrappedClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey + ".instruction")
      .build());

    String instructionFileContent = instructionFile.asUtf8String();
    JsonNodeParser parser = JsonNodeParser.create();
    JsonNode instructionFileNode = parser.parse(instructionFileContent);

    String originalIv = instructionFileNode.asObject().get("x-amz-iv").asString();
    String originalEncryptedDataKeyAlgorithm = instructionFileNode.asObject().get("x-amz-wrap-alg").asString();
    String originalEncryptedDataKey = instructionFileNode.asObject().get("x-amz-key-v2").asString();
    JsonNode originalMatDescNode = parser.parse(instructionFileNode.asObject().get("x-amz-matdesc").asString());
    assertEquals("no", originalMatDescNode.asObject().get("rotated").asString());

    AesKeyring newKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY_TWO)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("rotated", "yes")
        .build())
      .build();

    ReEncryptInstructionFileRequest reEncryptInstructionFileRequest = ReEncryptInstructionFileRequest.builder()
      .bucket(BUCKET)
      .key(objectKey)
      .newKeyring(newKeyring)
      .build();

    ReEncryptInstructionFileResponse response = client.reEncryptInstructionFile(reEncryptInstructionFileRequest);
    S3Client rotatedWrappedClient = S3Client.create();

    S3EncryptionClient rotatedClient = S3EncryptionClient.builder()
      .keyring(newKeyring)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(rotatedWrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    try {
      client.getObjectAsBytes(GetObjectRequest.builder()
        .bucket(BUCKET)
        .key(objectKey)
        .build());
      throw new RuntimeException("Expected exception");
    } catch (S3EncryptionClientException e) {
      assertTrue(e.getMessage().contains("Unable to AES/GCM unwrap"));
    }
    ResponseBytes<GetObjectResponse> getResponse = rotatedClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, getResponse.asUtf8String());

    ResponseBytes<GetObjectResponse> reEncryptedInstructionFile = rotatedWrappedClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey + ".instruction")
      .build());

    String newInstructionFileContent = reEncryptedInstructionFile.asUtf8String();
    JsonNode newInstructionFileNode = parser.parse(newInstructionFileContent);

    String postReEncryptionIv = newInstructionFileNode.asObject().get("x-amz-iv").asString();
    String postReEncryptionEncryptedDataKeyAlgorithm = newInstructionFileNode.asObject().get("x-amz-wrap-alg").asString();
    String postReEncryptionEncryptedDataKey = newInstructionFileNode.asObject().get("x-amz-key-v2").asString();
    JsonNode postReEncryptionMatDescNode = parser.parse(newInstructionFileNode.asObject().get("x-amz-matdesc").asString());

    assertEquals("yes", postReEncryptionMatDescNode.asObject().get("rotated").asString());
    assertEquals(originalIv, postReEncryptionIv);
    assertEquals(originalEncryptedDataKeyAlgorithm, postReEncryptionEncryptedDataKeyAlgorithm);
    assertNotEquals(originalEncryptedDataKey, postReEncryptionEncryptedDataKey);

    assertEquals(BUCKET, response.Bucket());
    assertEquals(objectKey, response.Key());
    assertEquals(".instruction", response.InstructionFileSuffix());

    deleteObject(BUCKET, objectKey, client);
  }

  @Test
  public void testRsaKeyringReEncryptInstructionFile() {
    PublicKey clientPublicKey = RSA_KEY_PAIR.getPublic();
    PrivateKey clientPrivateKey = RSA_KEY_PAIR.getPrivate();

    PartialRsaKeyPair clientPartialRsaKeyPair = PartialRsaKeyPair.builder()
      .publicKey(clientPublicKey)
      .privateKey(clientPrivateKey)
      .build();

    RsaKeyring clientKeyring = RsaKeyring.builder()
      .wrappingKeyPair(clientPartialRsaKeyPair)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("isOwner", "yes")
        .put("access-level", "admin")
        .build())
      .build();

    S3Client wrappedClient = S3Client.create();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(clientKeyring)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    final String objectKey = appendTestSuffix("rsa-re-encrypt-instruction-file-test");
    final String input = "Testing re-encryption of instruction file with RSA Keyring";

    client.putObject(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build(), RequestBody.fromString(input));

    PublicKey thirdPartyPublicKey = THIRD_PARTY_RSA_KEY_PAIR.getPublic();
    PrivateKey thirdPartyPrivateKey = THIRD_PARTY_RSA_KEY_PAIR.getPrivate();

    PartialRsaKeyPair thirdPartyPartialRsaKeyPair = PartialRsaKeyPair.builder()
      .publicKey(thirdPartyPublicKey)
      .privateKey(thirdPartyPrivateKey)
      .build();

    RsaKeyring thirdPartyKeyring = RsaKeyring.builder()
      .wrappingKeyPair(thirdPartyPartialRsaKeyPair)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("isOwner", "no")
        .put("access-level", "user")
        .build())
      .build();

    ReEncryptInstructionFileRequest reEncryptInstructionFileRequest = ReEncryptInstructionFileRequest.builder()
      .bucket(BUCKET)
      .key(objectKey)
      .instructionFileSuffix("third-party-access-instruction-file")
      .newKeyring(thirdPartyKeyring)
      .build();

    S3EncryptionClient thirdPartyClient = S3EncryptionClient.builder()
      .keyring(thirdPartyKeyring)
      .secureRandom(new SecureRandom())
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    ReEncryptInstructionFileResponse reEncryptInstructionFileResponse = client.reEncryptInstructionFile(reEncryptInstructionFileRequest);

    ResponseBytes<GetObjectResponse> clientInstructionFile= wrappedClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey + ".instruction")
      .build());

    JsonNodeParser parser = JsonNodeParser.create();

    String clientInstructionFileContent = clientInstructionFile.asUtf8String();

    JsonNode clientInstructionFileNode = parser.parse(clientInstructionFileContent);
    String clientIv = clientInstructionFileNode.asObject().get("x-amz-iv").asString();
    String clientEncryptedDataKeyAlgorithm = clientInstructionFileNode.asObject().get("x-amz-wrap-alg").asString();
    String clientEncryptedDataKey = clientInstructionFileNode.asObject().get("x-amz-key-v2").asString();
    JsonNode clientMatDescNode = parser.parse(clientInstructionFileNode.asObject().get("x-amz-matdesc").asString());

    assertEquals("yes", clientMatDescNode.asObject().get("isOwner").asString());
    assertEquals("admin", clientMatDescNode.asObject().get("access-level").asString());

    ResponseBytes<GetObjectResponse> thirdPartyInstFile = wrappedClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey + ".third-party-access-instruction-file")
      .build());

    String thirdPartyInstructionFileContent = thirdPartyInstFile.asUtf8String();
    JsonNode thirdPartyInstructionFileNode = parser.parse(thirdPartyInstructionFileContent);
    String thirdPartyIv = thirdPartyInstructionFileNode.asObject().get("x-amz-iv").asString();
    String thirdPartyEncryptedDataKeyAlgorithm = thirdPartyInstructionFileNode.asObject().get("x-amz-wrap-alg").asString();
    String thirdPartyEncryptedDataKey = thirdPartyInstructionFileNode.asObject().get("x-amz-key-v2").asString();
    JsonNode thirdPartyMatDescNode = parser.parse(thirdPartyInstructionFileNode.asObject().get("x-amz-matdesc").asString());
    assertEquals("no", thirdPartyMatDescNode.asObject().get("isOwner").asString());
    assertEquals("user", thirdPartyMatDescNode.asObject().get("access-level").asString());

    assertEquals(clientIv, thirdPartyIv);
    assertEquals(clientEncryptedDataKeyAlgorithm, thirdPartyEncryptedDataKeyAlgorithm);
    assertNotEquals(clientEncryptedDataKey, thirdPartyEncryptedDataKey);

    try {
      ResponseBytes<GetObjectResponse> thirdPartyDecryptObject = thirdPartyClient.getObjectAsBytes(builder -> builder
        .bucket(BUCKET)
        .key(objectKey)
        .build());
      throw new RuntimeException("Expected exception");
    } catch (S3EncryptionClientException e) {
      assertTrue(e.getMessage().contains("Unable to RSA-OAEP-SHA1 unwrap"));
    }

    ResponseBytes<GetObjectResponse> thirdPartyDecryptedObject = thirdPartyClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .overrideConfiguration(withCustomInstructionFileSuffix(".third-party-access-instruction-file"))
      .build());
    assertEquals(input, thirdPartyDecryptedObject.asUtf8String());

    ResponseBytes<GetObjectResponse> clientDecryptedObject = client.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, clientDecryptedObject.asUtf8String());

    assertEquals(BUCKET, reEncryptInstructionFileResponse.Bucket());
    assertEquals(objectKey, reEncryptInstructionFileResponse.Key());
    assertEquals(".third-party-access-instruction-file", reEncryptInstructionFileResponse.InstructionFileSuffix());

    deleteObject(BUCKET, objectKey, client);

  }

  @Test
  public void testReEncryptInstructionFileUpgradesV2AesToV3() {
    final String input = "Testing re-encryption of instruction file, upgrading legacy V2 AES to V3";
    final String objectKey = appendTestSuffix("v2-aes-to-v3-re-encrypt-instruction-file-test");

    EncryptionMaterialsProvider materialsProvider =
      new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY)
        .addDescription("rotated", "no")
        .addDescription("isLegacy", "yes")
      );

    CryptoConfigurationV2 cryptoConfig =
      new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
        .withStorageMode(CryptoStorageMode.InstructionFile);

    AmazonS3EncryptionV2 v2OriginalClient = AmazonS3EncryptionClientV2.encryptionBuilder()
      .withCryptoConfiguration(cryptoConfig)
      .withEncryptionMaterialsProvider(materialsProvider)
      .build();

    v2OriginalClient.putObject(BUCKET, objectKey, input);

    AesKeyring oldKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY)
      .enableLegacyWrappingAlgorithms(true)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("rotated", "no")
        .put("isLegacy", "yes")
        .build())
      .build();

    S3Client wrappedClient = S3Client.create();
    S3EncryptionClient v3OriginalClient = S3EncryptionClient.builder()
      .keyring(oldKeyring)
      .enableLegacyUnauthenticatedModes(true)
      .enableLegacyWrappingAlgorithms(true)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    AesKeyring newKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY_TWO)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("rotated", "yes")
        .put("isLegacy", "no")
        .build())
      .build();

    S3EncryptionClient v3RotatedClient = S3EncryptionClient.builder()
      .keyring(newKeyring)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    EncryptionMaterialsProvider newMaterialsProvider =
      new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY_TWO)
        .addDescription("rotated", "yes")
        .addDescription("isLegacy", "no")
      );

    CryptoConfigurationV2 newCryptoConfig =
      new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
        .withStorageMode(CryptoStorageMode.InstructionFile);

    AmazonS3EncryptionV2 v2RotatedClient = AmazonS3EncryptionClientV2.encryptionBuilder()
      .withCryptoConfiguration(newCryptoConfig)
      .withEncryptionMaterialsProvider(newMaterialsProvider)
      .build();

    ReEncryptInstructionFileRequest reEncryptInstructionFileRequest = ReEncryptInstructionFileRequest.builder()
      .bucket(BUCKET)
      .key(objectKey)
      .newKeyring(newKeyring)
      .build();

    ReEncryptInstructionFileResponse response = v3OriginalClient.reEncryptInstructionFile(reEncryptInstructionFileRequest);

    ResponseBytes<GetObjectResponse> v3DecryptObject = v3RotatedClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, v3DecryptObject.asUtf8String());

    ResponseBytes<GetObjectResponse> instructionFile = wrappedClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey + ".instruction")
      .build());

    JsonNodeParser parser = JsonNodeParser.create();
    JsonNode instructionFileNode = parser.parse(instructionFile.asUtf8String());
    String wrappingAlgorithm = instructionFileNode.asObject().get("x-amz-wrap-alg").asString();
    assertEquals("AES/GCM", wrappingAlgorithm);

    String v2DecryptObject = v2RotatedClient.getObjectAsString(BUCKET, objectKey);
    assertEquals(input, v2DecryptObject);

    deleteObject(BUCKET, objectKey, v3RotatedClient);

  }

  @Test
  public void testReEncryptInstructionFileUpgradesV2RsaToV3() throws IOException {
    final String input = "Testing re-encryption of instruction file, upgrading legacy V2 RSA to V3";
    final String objectKey = appendTestSuffix("v2-rsa-to-v3-re-encrypt-instruction-file-test");

    EncryptionMaterialsProvider materialsProvider =
      new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR)
        .addDescription("isOwner", "yes")
        .addDescription("access-level", "admin")
      );
    CryptoConfigurationV2 cryptoConfig =
      new CryptoConfigurationV2(CryptoMode.AuthenticatedEncryption)
        .withStorageMode(CryptoStorageMode.InstructionFile);

    AmazonS3EncryptionV2 v2OriginalClient = AmazonS3EncryptionClientV2.encryptionBuilder()
      .withCryptoConfiguration(cryptoConfig)
      .withEncryptionMaterialsProvider(materialsProvider)
      .build();

    v2OriginalClient.putObject(BUCKET, objectKey, input);

    PublicKey clientPublicKey = RSA_KEY_PAIR.getPublic();
    PrivateKey clientPrivateKey = RSA_KEY_PAIR.getPrivate();

    PartialRsaKeyPair clientPartialRsaKeyPair = PartialRsaKeyPair.builder()
      .publicKey(clientPublicKey)
      .privateKey(clientPrivateKey)
      .build();

    RsaKeyring clientKeyring = RsaKeyring.builder()
      .wrappingKeyPair(clientPartialRsaKeyPair)
      .secureRandom(new SecureRandom())
      .enableLegacyWrappingAlgorithms(true)
      .materialsDescription(MaterialsDescription.builder()
        .put("isOwner", "yes")
        .put("access-level", "admin")
        .build())
      .build();

    S3Client wrappedClient = S3Client.create();
    S3EncryptionClient v3OriginalClient = S3EncryptionClient.builder()
      .keyring(clientKeyring)
      .enableLegacyWrappingAlgorithms(true)
      .enableLegacyUnauthenticatedModes(true)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    PublicKey thirdPartyPublicKey = THIRD_PARTY_RSA_KEY_PAIR.getPublic();
    PrivateKey thirdPartyPrivateKey = THIRD_PARTY_RSA_KEY_PAIR.getPrivate();

    PartialRsaKeyPair thirdPartyPartialRsaKeyPair = PartialRsaKeyPair.builder()
      .publicKey(thirdPartyPublicKey)
      .privateKey(thirdPartyPrivateKey)
      .build();

    RsaKeyring thirdPartyKeyring = RsaKeyring.builder()
      .wrappingKeyPair(thirdPartyPartialRsaKeyPair)
      .secureRandom(new SecureRandom())
      .enableLegacyWrappingAlgorithms(true)
      .materialsDescription(MaterialsDescription.builder()
        .put("isOwner", "no")
        .put("access-level", "user")
        .build())
      .build();

    S3EncryptionClient v3ThirdPartyClient = S3EncryptionClient.builder()
      .keyring(thirdPartyKeyring)
      .enableLegacyWrappingAlgorithms(true)
      .enableLegacyUnauthenticatedModes(true)
      .secureRandom(new SecureRandom())
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    EncryptionMaterialsProvider thirdPartyMaterialsProvider =
      new StaticEncryptionMaterialsProvider(new EncryptionMaterials(THIRD_PARTY_RSA_KEY_PAIR)
        .addDescription("isOwner", "no")
        .addDescription("access-level", "user")
      );

    CryptoConfigurationV2 thirdPartyCryptoConfig =
      new CryptoConfigurationV2(CryptoMode.AuthenticatedEncryption)
        .withStorageMode(CryptoStorageMode.InstructionFile);

    AmazonS3EncryptionV2 v2ThirdPartyRotatedClient = AmazonS3EncryptionClientV2.encryptionBuilder()
      .withCryptoConfiguration(thirdPartyCryptoConfig)
      .withEncryptionMaterialsProvider(thirdPartyMaterialsProvider)
      .build();

    ReEncryptInstructionFileRequest reEncryptInstructionFileRequest = ReEncryptInstructionFileRequest.builder()
      .bucket(BUCKET)
      .key(objectKey)
      .newKeyring(thirdPartyKeyring)
      .instructionFileSuffix("third-party-access-instruction-file")
      .build();

    ReEncryptInstructionFileResponse response = v3OriginalClient.reEncryptInstructionFile(reEncryptInstructionFileRequest);

    ResponseBytes<GetObjectResponse> v3DecryptObject = v3OriginalClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, v3DecryptObject.asUtf8String());

    String v2DecryptObject = v2OriginalClient.getObjectAsString(BUCKET, objectKey);
    assertEquals(input, v2DecryptObject);

    ResponseBytes<GetObjectResponse> thirdPartyDecryptedObject = v3ThirdPartyClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .overrideConfiguration(withCustomInstructionFileSuffix(".third-party-access-instruction-file"))
      .build());

    assertEquals(input, thirdPartyDecryptedObject.asUtf8String());

    EncryptedGetObjectRequest request = new EncryptedGetObjectRequest(BUCKET, objectKey)
      .withInstructionFileSuffix("third-party-access-instruction-file");

    String v2ThirdPartyDecryptObject = IOUtils.toString(v2ThirdPartyRotatedClient.getObject(request).getObjectContent(), StandardCharsets.UTF_8);
    assertEquals(input, v2ThirdPartyDecryptObject);

    deleteObject(BUCKET, objectKey, v3OriginalClient);

  }

  @Test
  public void testReEncryptInstructionFileUpgradesV1AesToV3() {
    final String input = "Testing re-encryption of instruction file, upgrading legacy V1 AES to V3";
    final String objectKey = appendTestSuffix("v1-aes-to-v3-re-encrypt-instruction-file-test");

    EncryptionMaterialsProvider materialsProvider =
      new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY)
        .addDescription("rotated", "no")
        .addDescription("isLegacy", "yes")
      );

    CryptoConfiguration cryptoConfig = new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
        .withStorageMode(CryptoStorageMode.InstructionFile);

    AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
      .withCryptoConfiguration(cryptoConfig)
      .withEncryptionMaterials(materialsProvider)
      .build();

    v1Client.putObject(BUCKET, objectKey, input);

    AesKeyring oldKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY)
      .enableLegacyWrappingAlgorithms(true)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("rotated", "no")
        .put("isLegacy", "yes")
        .build())
      .build();

    S3Client wrappedClient = S3Client.create();
    S3EncryptionClient v3OriginalClient = S3EncryptionClient.builder()
      .keyring(oldKeyring)
      .enableLegacyUnauthenticatedModes(true)
      .enableLegacyWrappingAlgorithms(true)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    AesKeyring newKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY_TWO)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("rotated", "yes")
        .put("isLegacy", "no")
        .build())
      .build();

    S3EncryptionClient v3RotatedClient = S3EncryptionClient.builder()
      .keyring(newKeyring)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    EncryptionMaterialsProvider newMaterialsProvider =
      new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY_TWO)
        .addDescription("rotated", "yes")
        .addDescription("isLegacy", "no")
      );

    CryptoConfiguration newCryptoConfig =
      new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
        .withStorageMode(CryptoStorageMode.InstructionFile);

    AmazonS3Encryption v1RotatedClient = AmazonS3EncryptionClient.encryptionBuilder()
      .withCryptoConfiguration(newCryptoConfig)
      .withEncryptionMaterials(newMaterialsProvider)
      .build();

    ReEncryptInstructionFileRequest reEncryptInstructionFileRequest = ReEncryptInstructionFileRequest.builder()
      .bucket(BUCKET)
      .key(objectKey)
      .newKeyring(newKeyring)
      .build();

    ReEncryptInstructionFileResponse response = v3OriginalClient.reEncryptInstructionFile(reEncryptInstructionFileRequest);

    ResponseBytes<GetObjectResponse> v3DecryptObject = v3RotatedClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, v3DecryptObject.asUtf8String());

    ResponseBytes<GetObjectResponse> instructionFile = wrappedClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey + ".instruction")
      .build());

    JsonNodeParser parser = JsonNodeParser.create();
    JsonNode instructionFileNode = parser.parse(instructionFile.asUtf8String());
    String wrappingAlgorithm = instructionFileNode.asObject().get("x-amz-wrap-alg").asString();
    assertEquals("AES/GCM", wrappingAlgorithm);

    String v1DecryptObject = v1RotatedClient.getObjectAsString(BUCKET, objectKey);
    assertEquals(input, v1DecryptObject);

    deleteObject(BUCKET, objectKey, v3RotatedClient);

  }

  @Test
  public void testReEncryptInstructionFileUpgradesV1RsaToV3() throws IOException {
    final String input = "Testing re-encryption of instruction file, upgrading legacy V1 RSA to V3";
    final String objectKey = appendTestSuffix("v1-rsa-to-v3-re-encrypt-instruction-file-test");

    EncryptionMaterialsProvider materialsProvider =
      new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR)
        .addDescription("isOwner", "yes")
        .addDescription("access-level", "admin")
      );
    CryptoConfiguration cryptoConfig =
      new CryptoConfiguration(CryptoMode.StrictAuthenticatedEncryption)
        .withStorageMode(CryptoStorageMode.InstructionFile);

    AmazonS3Encryption v1OriginalClient = AmazonS3EncryptionClient.encryptionBuilder()
      .withCryptoConfiguration(cryptoConfig)
      .withEncryptionMaterials(materialsProvider)
      .build();

    v1OriginalClient.putObject(BUCKET, objectKey, input);

    PublicKey clientPublicKey = RSA_KEY_PAIR.getPublic();
    PrivateKey clientPrivateKey = RSA_KEY_PAIR.getPrivate();

    PartialRsaKeyPair clientPartialRsaKeyPair = PartialRsaKeyPair.builder()
      .publicKey(clientPublicKey)
      .privateKey(clientPrivateKey)
      .build();

    RsaKeyring clientKeyring = RsaKeyring.builder()
      .wrappingKeyPair(clientPartialRsaKeyPair)
      .secureRandom(new SecureRandom())
      .enableLegacyWrappingAlgorithms(true)
      .materialsDescription(MaterialsDescription.builder()
        .put("isOwner", "yes")
        .put("access-level", "admin")
        .build())
      .build();

    S3Client wrappedClient = S3Client.create();
    S3EncryptionClient v3OriginalClient = S3EncryptionClient.builder()
      .keyring(clientKeyring)
      .enableLegacyWrappingAlgorithms(true)
      .enableLegacyUnauthenticatedModes(true)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    PublicKey thirdPartyPublicKey = THIRD_PARTY_RSA_KEY_PAIR.getPublic();
    PrivateKey thirdPartyPrivateKey = THIRD_PARTY_RSA_KEY_PAIR.getPrivate();

    PartialRsaKeyPair thirdPartyPartialRsaKeyPair = PartialRsaKeyPair.builder()
      .publicKey(thirdPartyPublicKey)
      .privateKey(thirdPartyPrivateKey)
      .build();

    RsaKeyring thirdPartyKeyring = RsaKeyring.builder()
      .wrappingKeyPair(thirdPartyPartialRsaKeyPair)
      .secureRandom(new SecureRandom())
      .enableLegacyWrappingAlgorithms(true)
      .materialsDescription(MaterialsDescription.builder()
        .put("isOwner", "no")
        .put("access-level", "user")
        .build())
      .build();

    S3EncryptionClient v3ThirdPartyClient = S3EncryptionClient.builder()
      .keyring(thirdPartyKeyring)
      .enableLegacyWrappingAlgorithms(true)
      .enableLegacyUnauthenticatedModes(true)
      .secureRandom(new SecureRandom())
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    EncryptionMaterialsProvider thirdPartyMaterialsProvider =
      new StaticEncryptionMaterialsProvider(new EncryptionMaterials(THIRD_PARTY_RSA_KEY_PAIR)
        .addDescription("isOwner", "no")
        .addDescription("access-level", "user")
      );

    CryptoConfiguration thirdPartyCryptoConfig =
      new CryptoConfiguration(CryptoMode.StrictAuthenticatedEncryption)
        .withStorageMode(CryptoStorageMode.InstructionFile);

    AmazonS3Encryption v1ThirdPartyRotatedClient = AmazonS3EncryptionClient.encryptionBuilder()
      .withCryptoConfiguration(thirdPartyCryptoConfig)
      .withEncryptionMaterials(thirdPartyMaterialsProvider)
      .build();

    ReEncryptInstructionFileRequest reEncryptInstructionFileRequest = ReEncryptInstructionFileRequest.builder()
      .bucket(BUCKET)
      .key(objectKey)
      .newKeyring(thirdPartyKeyring)
      .instructionFileSuffix("third-party-access-instruction-file")
      .build();

    ReEncryptInstructionFileResponse response = v3OriginalClient.reEncryptInstructionFile(reEncryptInstructionFileRequest);

    ResponseBytes<GetObjectResponse> v3DecryptObject = v3OriginalClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, v3DecryptObject.asUtf8String());

    String v2DecryptObject = v1OriginalClient.getObjectAsString(BUCKET, objectKey);
    assertEquals(input, v2DecryptObject);

    ResponseBytes<GetObjectResponse> thirdPartyDecryptedObject = v3ThirdPartyClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .overrideConfiguration(withCustomInstructionFileSuffix(".third-party-access-instruction-file"))
      .build());

    assertEquals(input, thirdPartyDecryptedObject.asUtf8String());

    EncryptedGetObjectRequest request = new EncryptedGetObjectRequest(BUCKET, objectKey)
      .withInstructionFileSuffix("third-party-access-instruction-file");

    String v1ThirdPartyDecryptObject = IOUtils.toString(v1ThirdPartyRotatedClient.getObject(request).getObjectContent(), StandardCharsets.UTF_8);
    assertEquals(input, v1ThirdPartyDecryptObject);

    deleteObject(BUCKET, objectKey, v3OriginalClient);

  }

  @Test
  public void testReEncryptInstructionFileUpgradesV1AesEncryptionOnlyToV3() {
    final String input = "Testing re-encryption of instruction file, upgrading legacy V1 Encryption Only AES to V3";
    final String objectKey = appendTestSuffix("v1-aes-encryption-only-to-v3-re-encrypt-instruction-file-test");

    EncryptionMaterialsProvider materialsProvider =
      new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY)
        .addDescription("rotated", "no")
        .addDescription("isLegacy", "yes")
      );

    CryptoConfiguration cryptoConfig =
      new CryptoConfiguration(CryptoMode.EncryptionOnly)
        .withStorageMode(CryptoStorageMode.InstructionFile);

    AmazonS3Encryption v1OriginalClient = AmazonS3EncryptionClient.encryptionBuilder()
      .withCryptoConfiguration(cryptoConfig)
      .withEncryptionMaterials(materialsProvider)
      .build();

    v1OriginalClient.putObject(BUCKET, objectKey, input);

    AesKeyring oldKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY)
      .enableLegacyWrappingAlgorithms(true)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("rotated", "no")
        .put("isLegacy", "yes")
        .build())
      .build();

    S3Client wrappedClient = S3Client.create();
    S3EncryptionClient v3OriginalClient = S3EncryptionClient.builder()
      .keyring(oldKeyring)
      .enableLegacyUnauthenticatedModes(true)
      .enableLegacyWrappingAlgorithms(true)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    AesKeyring newKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY_TWO)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("rotated", "yes")
        .put("isLegacy", "no")
        .build())
      .build();

    S3EncryptionClient v3RotatedClient = S3EncryptionClient.builder()
      .keyring(newKeyring)
      .enableLegacyWrappingAlgorithms(true)
      .enableLegacyUnauthenticatedModes(true)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    EncryptionMaterialsProvider newMaterialsProvider =
      new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY_TWO)
        .addDescription("rotated", "yes")
        .addDescription("isLegacy", "no")
      );

    CryptoConfiguration newCryptoConfig =
      new CryptoConfiguration(CryptoMode.EncryptionOnly)
        .withStorageMode(CryptoStorageMode.InstructionFile);

    AmazonS3Encryption v1RotatedClient = AmazonS3EncryptionClient.encryptionBuilder()
      .withCryptoConfiguration(newCryptoConfig)
      .withEncryptionMaterials(newMaterialsProvider)
      .build();

    ReEncryptInstructionFileRequest reEncryptInstructionFileRequest = ReEncryptInstructionFileRequest.builder()
      .bucket(BUCKET)
      .key(objectKey)
      .newKeyring(newKeyring)
      .build();

    ReEncryptInstructionFileResponse response = v3OriginalClient.reEncryptInstructionFile(reEncryptInstructionFileRequest);

    ResponseBytes<GetObjectResponse> v3DecryptObject = v3RotatedClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, v3DecryptObject.asUtf8String());

    ResponseBytes<GetObjectResponse> instructionFile = wrappedClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey + ".instruction")
      .build());

    JsonNodeParser parser = JsonNodeParser.create();
    JsonNode instructionFileNode = parser.parse(instructionFile.asUtf8String());
    String wrappingAlgorithm = instructionFileNode.asObject().get("x-amz-wrap-alg").asString();
    assertEquals("AES/GCM", wrappingAlgorithm);

    try {
      String v1DecryptObject = v1RotatedClient.getObjectAsString(BUCKET, objectKey);
      throw new RuntimeException("V1 client with EncryptionOnly cannot decrypt content after V3 re-encryption due to AES/GCM algorithm upgrade");
    } catch (AmazonClientException e) {
      assertTrue(e.getMessage().contains("An exception was thrown when attempting to decrypt the Content Encryption Key"));
    }

    deleteObject(BUCKET, objectKey, v3RotatedClient);

  }
  @Test
  public void testReEncryptInstructionFileUpgradesV1RsaEncryptionOnlyToV3() throws IOException {
    final String input = "Testing re-encryption of instruction file, upgrading legacy V1 Encryption Only RSA to V3";
    final String objectKey = appendTestSuffix("v1-rsa-encryption-only-to-v3-re-encrypt-instruction-file-test");

    EncryptionMaterialsProvider materialsProvider =
      new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR)
        .addDescription("isOwner", "yes")
        .addDescription("access-level", "admin")
      );
    CryptoConfiguration cryptoConfig =
      new CryptoConfiguration(CryptoMode.EncryptionOnly)
        .withStorageMode(CryptoStorageMode.InstructionFile);

    AmazonS3Encryption v1OriginalClient = AmazonS3EncryptionClient.encryptionBuilder()
      .withCryptoConfiguration(cryptoConfig)
      .withEncryptionMaterials(materialsProvider)
      .build();

    v1OriginalClient.putObject(BUCKET, objectKey, input);

    PublicKey clientPublicKey = RSA_KEY_PAIR.getPublic();
    PrivateKey clientPrivateKey = RSA_KEY_PAIR.getPrivate();

    PartialRsaKeyPair clientPartialRsaKeyPair = PartialRsaKeyPair.builder()
      .publicKey(clientPublicKey)
      .privateKey(clientPrivateKey)
      .build();

    RsaKeyring clientKeyring = RsaKeyring.builder()
      .wrappingKeyPair(clientPartialRsaKeyPair)
      .secureRandom(new SecureRandom())
      .enableLegacyWrappingAlgorithms(true)
      .materialsDescription(MaterialsDescription.builder()
        .put("isOwner", "yes")
        .put("access-level", "admin")
        .build())
      .build();

    S3Client wrappedClient = S3Client.create();
    S3EncryptionClient v3OriginalClient = S3EncryptionClient.builder()
      .keyring(clientKeyring)
      .enableLegacyWrappingAlgorithms(true)
      .enableLegacyUnauthenticatedModes(true)
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    PublicKey thirdPartyPublicKey = THIRD_PARTY_RSA_KEY_PAIR.getPublic();
    PrivateKey thirdPartyPrivateKey = THIRD_PARTY_RSA_KEY_PAIR.getPrivate();

    PartialRsaKeyPair thirdPartyPartialRsaKeyPair = PartialRsaKeyPair.builder()
      .publicKey(thirdPartyPublicKey)
      .privateKey(thirdPartyPrivateKey)
      .build();

    RsaKeyring thirdPartyKeyring = RsaKeyring.builder()
      .wrappingKeyPair(thirdPartyPartialRsaKeyPair)
      .secureRandom(new SecureRandom())
      .enableLegacyWrappingAlgorithms(true)
      .materialsDescription(MaterialsDescription.builder()
        .put("isOwner", "no")
        .put("access-level", "user")
        .build())
      .build();

    S3EncryptionClient v3ThirdPartyClient = S3EncryptionClient.builder()
      .keyring(thirdPartyKeyring)
      .enableLegacyWrappingAlgorithms(true)
      .enableLegacyUnauthenticatedModes(true)
      .secureRandom(new SecureRandom())
      .instructionFileConfig(InstructionFileConfig.builder()
        .instructionFileClient(wrappedClient)
        .enableInstructionFilePutObject(true)
        .build())
      .build();

    EncryptionMaterialsProvider thirdPartyMaterialsProvider =
      new StaticEncryptionMaterialsProvider(new EncryptionMaterials(THIRD_PARTY_RSA_KEY_PAIR)
        .addDescription("isOwner", "no")
        .addDescription("access-level", "user")
      );

    CryptoConfiguration thirdPartyCryptoConfig = new CryptoConfiguration(CryptoMode.EncryptionOnly)
        .withStorageMode(CryptoStorageMode.InstructionFile);

    AmazonS3Encryption v1ThirdPartyRotatedClient = AmazonS3EncryptionClient.encryptionBuilder()
      .withCryptoConfiguration(thirdPartyCryptoConfig)
      .withEncryptionMaterials(thirdPartyMaterialsProvider)
      .build();

    ReEncryptInstructionFileRequest reEncryptInstructionFileRequest = ReEncryptInstructionFileRequest.builder()
      .bucket(BUCKET)
      .key(objectKey)
      .newKeyring(thirdPartyKeyring)
      .instructionFileSuffix("third-party-access-instruction-file")
      .build();

    ReEncryptInstructionFileResponse response = v3OriginalClient.reEncryptInstructionFile(reEncryptInstructionFileRequest);

    ResponseBytes<GetObjectResponse> v3DecryptObject = v3OriginalClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, v3DecryptObject.asUtf8String());

    String v1DecryptObject = v1OriginalClient.getObjectAsString(BUCKET, objectKey);
    assertEquals(input, v1DecryptObject);

    ResponseBytes<GetObjectResponse> thirdPartyDecryptedObject = v3ThirdPartyClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .overrideConfiguration(withCustomInstructionFileSuffix(".third-party-access-instruction-file"))
      .build());

    assertEquals(input, thirdPartyDecryptedObject.asUtf8String());

    EncryptedGetObjectRequest request = new EncryptedGetObjectRequest(BUCKET, objectKey)
      .withInstructionFileSuffix("third-party-access-instruction-file");

    try {
      String v1ThirdPartyDecryptObject = IOUtils.toString(v1ThirdPartyRotatedClient.getObject(request).getObjectContent(), StandardCharsets.UTF_8);
      throw new RuntimeException("V1 client with EncryptionOnly cannot decrypt content after V3 re-encryption due to RSA algorithm upgrade");
    } catch (SecurityException e) {
      assertTrue(e.getMessage().contains("The content encryption algorithm used at encryption time does not match the algorithm stored for decryption time. The object may be altered or corrupted."));
    }

    deleteObject(BUCKET, objectKey, v3OriginalClient);

  }
}
