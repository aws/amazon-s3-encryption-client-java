package software.amazon.encryption.s3;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;
import software.amazon.encryption.s3.internal.InstructionFileConfig;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.MaterialsDescription;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;
import software.amazon.encryption.s3.materials.RsaKeyring;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class S3EncryptionClientMatDescTest {
  private static SecretKey AES_KEY;
  private static KeyPair RSA_KEY_PAIR;

  @BeforeAll
  public static void setUp() throws NoSuchAlgorithmException {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(256);
    AES_KEY = keyGen.generateKey();

    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(2048);
    RSA_KEY_PAIR = keyPairGen.generateKeyPair();
  }

  @Test
  public void testAesMaterialsDescriptionInObjectMetadata() {
    AesKeyring aesKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("version", "1.0")
        .build())
      .build();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(aesKeyring)
      .build();
    final String input = "Testing Materials Description in Object Metadata!";
    final String objectKey = appendTestSuffix("test-aes-materials-description-in-object-metadata");

    client.putObject(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build(), RequestBody.fromString(input)
    );
    ResponseBytes<GetObjectResponse> responseBytes = client.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, responseBytes.asUtf8String());

    JsonNodeParser parser = JsonNodeParser.create();
    JsonNode matDescNode = parser.parse(responseBytes.response().metadata().get("x-amz-matdesc"));
    assertEquals("1.0", matDescNode.asObject().get("version").asString());

    deleteObject(BUCKET, objectKey, client);

  }

  @Test
  public void testRsaMaterialsDescriptionInObjectMetadata() {
    PartialRsaKeyPair keyPair = new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), RSA_KEY_PAIR.getPublic());
    RsaKeyring rsaKeyring = RsaKeyring.builder()
      .wrappingKeyPair(keyPair)
      .materialsDescription(MaterialsDescription.builder()
        .put("version", "1.0")
        .put("admin", "yes")
        .build())
      .build();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(rsaKeyring)
      .build();
    final String input = "Testing Materials Description in Instruction File!";
    final String objectKey = appendTestSuffix("test-rsa-materials-description-in-instruction-file");

    client.putObject(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build(), RequestBody.fromString(input)
    );
    ResponseBytes<GetObjectResponse> responseBytes = client.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, responseBytes.asUtf8String());

    JsonNodeParser parser = JsonNodeParser.create();
    JsonNode matDescNode = parser.parse(responseBytes.response().metadata().get("x-amz-matdesc"));
    assertEquals("1.0", matDescNode.asObject().get("version").asString());
    assertEquals("yes", matDescNode.asObject().get("admin").asString());

    deleteObject(BUCKET, objectKey, client);

  }

  @Test
  public void testAesMaterialsDescriptionInInstructionFile() {
    AesKeyring aesKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("version", "1.0")
        .build())
      .build();

    S3Client wrappedClient= S3Client.create();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(aesKeyring)
      .instructionFileConfig(InstructionFileConfig.builder()
        .enableInstructionFilePutObject(true)
        .instructionFileClient(wrappedClient)
        .build())
      .build();

    final String input = "Testing Materials Description in Instruction File!";
    final String objectKey = appendTestSuffix("test-aes-materials-description-in-instruction-file");

    client.putObject(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build(), RequestBody.fromString(input)
    );
    ResponseBytes<GetObjectResponse> responseBytes = client.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, responseBytes.asUtf8String());

    S3Client defaultClient= S3Client.create();

    ResponseBytes<GetObjectResponse> directInstGetResponse = defaultClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey + ".instruction")
      .build());

    String instructionFileContent = directInstGetResponse.asUtf8String();
    JsonNodeParser parser = JsonNodeParser.create();
    JsonNode instructionFileNode = parser.parse(instructionFileContent);

    JsonNode matDescNode = parser.parse(instructionFileNode.asObject().get("x-amz-matdesc").asString());
    assertEquals("1.0", matDescNode.asObject().get("version").asString());

    deleteObject(BUCKET, objectKey, client);

  }

  @Test
  public void testRsaMaterialsDescriptionInInstructionFile() {
    PartialRsaKeyPair keyPair = new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), RSA_KEY_PAIR.getPublic());

    RsaKeyring rsaKeyring = RsaKeyring.builder()
      .wrappingKeyPair(keyPair)
      .materialsDescription(MaterialsDescription.builder()
        .put("version", "1.0")
        .put("admin", "yes")
        .build())
      .build();

    S3Client wrappedClient= S3Client.create();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(rsaKeyring)
      .instructionFileConfig(InstructionFileConfig.builder()
        .enableInstructionFilePutObject(true)
        .instructionFileClient(wrappedClient)
        .build())
      .build();

    final String input = "Testing Materials Description in Instruction File!";
    final String objectKey = appendTestSuffix("test-rsa-materials-description-in-instruction-file");

    client.putObject(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build(), RequestBody.fromString(input)
    );
    ResponseBytes<GetObjectResponse> responseBytes = client.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, responseBytes.asUtf8String());

    S3Client defaultClient= S3Client.create();

    ResponseBytes<GetObjectResponse> directInstGetResponse = defaultClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey + ".instruction")
      .build());

    String instructionFileContent = directInstGetResponse.asUtf8String();
    JsonNodeParser parser = JsonNodeParser.create();
    JsonNode instructionFileNode = parser.parse(instructionFileContent);

    JsonNode matDescNode = parser.parse(instructionFileNode.asObject().get("x-amz-matdesc").asString());
    assertEquals("1.0", matDescNode.asObject().get("version").asString());
    assertEquals("yes", matDescNode.asObject().get("admin").asString());

    deleteObject(BUCKET, objectKey, client);
  }

  @Test
  public void testAesKeyringMatDescOverridesPutObjectEncryptionContext() {
    AesKeyring aesKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY)
      .secureRandom(new SecureRandom())
      .materialsDescription(MaterialsDescription.builder()
        .put("version", "1.0")
        .build())
      .build();

    S3Client wrappedClient= S3Client.create();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(aesKeyring)
      .instructionFileConfig(InstructionFileConfig.builder()
        .enableInstructionFilePutObject(true)
        .instructionFileClient(wrappedClient)
        .build())
      .build();

    final String input = "Testing Materials Description in Instruction File and not Encryption Context!";
    final String objectKey = appendTestSuffix("test-aes-materials-description-in-instruction-file-and-not-encryption-context");
    final Map<String, String> encryptionContext = new HashMap<String, String>();
    encryptionContext.put("admin", "yes");

    client.putObject(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
      .build(), RequestBody.fromString(input)
    );
    ResponseBytes<GetObjectResponse> responseBytes = client.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, responseBytes.asUtf8String());

    S3Client defaultClient= S3Client.create();

    ResponseBytes<GetObjectResponse> directInstGetResponse = defaultClient.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey + ".instruction")
      .build());

    String instructionFileContent = directInstGetResponse.asUtf8String();
    JsonNodeParser parser = JsonNodeParser.create();
    JsonNode instructionFileNode = parser.parse(instructionFileContent);

    JsonNode matDescNode = parser.parse(instructionFileNode.asObject().get("x-amz-matdesc").asString());
    assertEquals("1.0", matDescNode.asObject().get("version").asString());
    assertNull(matDescNode.asObject().get("admin"));

  }

  @Test
  public void testRsaKeyringMatDescOverridesPutObjectEncryptionContext() {
    PartialRsaKeyPair keyPair = new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), RSA_KEY_PAIR.getPublic());
    RsaKeyring rsaKeyring = RsaKeyring.builder()
      .wrappingKeyPair(keyPair)
      .materialsDescription(MaterialsDescription.builder()
        .put("version", "1.0")
        .build())
      .build();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(rsaKeyring)
      .build();
    final String input = "Testing Materials Description in Instruction File and not Encryption Context!";
    final String objectKey = appendTestSuffix("test-rsa-materials-description-in-instruction-file-and-not-encryption-context");
    final Map<String, String> encryptionContext = new HashMap<String, String>();
    encryptionContext.put("admin", "yes");

    client.putObject(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
      .build(), RequestBody.fromString(input)
    );
    ResponseBytes<GetObjectResponse> responseBytes = client.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    assertEquals(input, responseBytes.asUtf8String());

    JsonNodeParser parser = JsonNodeParser.create();
    JsonNode matDescNode = parser.parse(responseBytes.response().metadata().get("x-amz-matdesc"));
    assertEquals("1.0", matDescNode.asObject().get("version").asString());
    assertNull(matDescNode.asObject().get("admin"));

  }

}
