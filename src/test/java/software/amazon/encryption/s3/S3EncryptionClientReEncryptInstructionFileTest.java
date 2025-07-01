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
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.MaterialsDescription;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;
import software.amazon.encryption.s3.materials.RsaKeyring;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
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

}
