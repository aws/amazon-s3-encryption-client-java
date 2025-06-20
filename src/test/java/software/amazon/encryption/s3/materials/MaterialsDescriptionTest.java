package software.amazon.encryption.s3.materials;


import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;

import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.internal.InstructionFileConfig;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class MaterialsDescriptionTest {
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
  public void testSimpleMaterialsDescription() {
    MaterialsDescription materialsDescription = MaterialsDescription.builder()
      .put("version", "1.0")
      .build();
    assertEquals("1.0", materialsDescription.getMaterialsDescription().get("version"));
    assertEquals(1, materialsDescription.getMaterialsDescription().size());
    try {
      materialsDescription.getMaterialsDescription().put("version", "2.0");
      fail("Expected UnsupportedOperationException!");
    } catch (UnsupportedOperationException e) {
      assertNull(e.getMessage());
    }
    try {
      materialsDescription.getMaterialsDescription().clear();
      fail("Expected UnsupportedOperationException!");
    } catch (UnsupportedOperationException e) {
      assertNull(e.getMessage());
    }
  }
  @Test
  public void testMaterialsDescriptionPutAll() {
    Map<String, String> description = new HashMap<>();
    description.put("version", "1.0");
    description.put("next-version", "2.0");
    MaterialsDescription materialsDescription = MaterialsDescription.builder()
      .putAll(description)
      .build();
    assertEquals(2, materialsDescription.getMaterialsDescription().size());
    assertTrue(materialsDescription.getMaterialsDescription().containsKey("version"));
    assertTrue(materialsDescription.getMaterialsDescription().containsKey("next-version"));
    assertEquals("1.0", materialsDescription.getMaterialsDescription().get("version"));
    assertEquals("2.0", materialsDescription.getMaterialsDescription().get("next-version"));
  }
  @Test
  public void testMaterialsDescriptionAesKeyring() {
    AesKeyring aesKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY)
      .reEncryptInstructionFile(true)
      .materialsDescription(MaterialsDescription.builder()
        .put("version", "1.0")
        .put("admin", "yes")
        .build())
      .build();
    assertNotNull(aesKeyring.getMaterialsDescription());
    assertEquals("1.0", aesKeyring.getMaterialsDescription().getMaterialsDescription().get("version"));
    assertEquals("yes", aesKeyring.getMaterialsDescription().getMaterialsDescription().get("admin"));
    assertEquals(2, aesKeyring.getMaterialsDescription().getMaterialsDescription().size());

  }
  @Test
  public void testMaterialsDescriptionRsaKeyring() {
    PartialRsaKeyPair keyPair = new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), RSA_KEY_PAIR.getPublic());
    RsaKeyring rsaKeyring = RsaKeyring.builder()
      .wrappingKeyPair(keyPair)
      .reEncryptInstructionFile(true)
      .materialsDescription(MaterialsDescription.builder()
        .put("version", "1.0")
        .put("admin", "yes")
        .build())
      .build();
    assertNotNull(rsaKeyring);
    assertEquals("1.0", rsaKeyring.getMaterialsDescription().getMaterialsDescription().get("version"));
    assertEquals("yes", rsaKeyring.getMaterialsDescription().getMaterialsDescription().get("admin"));
    assertEquals(2, rsaKeyring.getMaterialsDescription().getMaterialsDescription().size());

  }
  @Test
  public void testAesMaterialsDescriptionInObjectMetadata() {
    MaterialsDescription materialsDescription = MaterialsDescription.builder()
      .put("version", "1.0")
      .build();
    AesKeyring aesKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY)
      .reEncryptInstructionFile(true)
      .secureRandom(new SecureRandom())
      .materialsDescription(materialsDescription)
      .build();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(aesKeyring)
      .build();
    final String input = "Testing Materials Description in Object Metadata!";
    final String objectKey = "test-aes-materials-description-in-object-metadata";

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
    assertEquals("{\"version\":\"1.0\"}", responseBytes.response().metadata().get("x-amz-matdesc"));

    deleteObject(BUCKET, objectKey, client);

  }
  @Test
  public void testRsaMaterialsDescriptionInObjectMetadata() {
    PartialRsaKeyPair keyPair = new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), RSA_KEY_PAIR.getPublic());
    MaterialsDescription materialsDescription = MaterialsDescription.builder()
      .put("version", "1.0")
      .put("admin", "yes")
      .build();
    RsaKeyring rsaKeyring = RsaKeyring.builder()
      .wrappingKeyPair(keyPair)
      .reEncryptInstructionFile(true)
      .materialsDescription(materialsDescription)
      .build();
    S3EncryptionClient client = S3EncryptionClient.builder()
      .keyring(rsaKeyring)
      .build();
    final String input = "Testing Materials Description in Instruction File!";
    final String objectKey = "test-rsa-materials-description-in-instruction-file";

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
    assertEquals("{\"admin\":\"yes\",\"version\":\"1.0\"}", responseBytes.response().metadata().get("x-amz-matdesc"));

    deleteObject(BUCKET, objectKey, client);

  }
  @Test
  public void testAesMaterialsDescriptionInInstructionFile() {
    MaterialsDescription materialsDescription = MaterialsDescription.builder()
      .put("version", "1.0")
      .build();
    AesKeyring aesKeyring = AesKeyring.builder()
      .wrappingKey(AES_KEY)
      .reEncryptInstructionFile(true)
      .secureRandom(new SecureRandom())
      .materialsDescription(materialsDescription)
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
    final String objectKey = "test-aes-materials-description-in-instruction-file";

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
    JsonNode objectNode = parser.parse(instructionFileContent);

    String matDesc = objectNode.asObject().get("x-amz-matdesc").asString();
    assertEquals("{\"version\":\"1.0\"}", matDesc);

  }
  @Test
  public void testRsaMaterialsDescriptionInInstructionFile() {
    PartialRsaKeyPair keyPair = new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), RSA_KEY_PAIR.getPublic());
    MaterialsDescription materialsDescription = MaterialsDescription.builder()
      .put("version", "1.0")
      .put("admin", "yes")
      .build();

    RsaKeyring rsaKeyring = RsaKeyring.builder()
      .wrappingKeyPair(keyPair)
      .reEncryptInstructionFile(true)
      .materialsDescription(materialsDescription)
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
    final String objectKey = "test-rsa-materials-description-in-instruction-file";

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
    JsonNode objectNode = parser.parse(instructionFileContent);

    String matDesc = objectNode.asObject().get("x-amz-matdesc").asString();
    assertEquals("{\"admin\":\"yes\",\"version\":\"1.0\"}", matDesc);


    deleteObject(BUCKET, objectKey, client);

  }

}