package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.S3EncryptionClientException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    assertEquals("1.0", materialsDescription.getDescription().get("version"));
    assertEquals(1, materialsDescription.getDescription().size());
    try {
      materialsDescription.getDescription().put("version", "2.0");
      throw new RuntimeException("Expected UnsupportedOperationException");
    } catch (UnsupportedOperationException e) {
      assertNull(e.getMessage());
    }
    try {
      materialsDescription.getDescription().clear();
      throw new RuntimeException("Expected UnsupportedOperationException");
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
    assertEquals(2, materialsDescription.getDescription().size());
    assertTrue(materialsDescription.getDescription().containsKey("version"));
    assertTrue(materialsDescription.getDescription().containsKey("next-version"));
    assertEquals("1.0", materialsDescription.getDescription().get("version"));
    assertEquals("2.0", materialsDescription.getDescription().get("next-version"));
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
    assertEquals("1.0", aesKeyring.getMaterialsDescription().getDescription().get("version"));
    assertEquals("yes", aesKeyring.getMaterialsDescription().getDescription().get("admin"));
    assertEquals(2, aesKeyring.getMaterialsDescription().getDescription().size());

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
    assertEquals("1.0", rsaKeyring.getMaterialsDescription().getDescription().get("version"));
    assertEquals("yes", rsaKeyring.getMaterialsDescription().getDescription().get("admin"));
    assertEquals(2, rsaKeyring.getMaterialsDescription().getDescription().size());

  }
  @Test
  public void testMaterialsDescriptionRsaKeyringWithNoReEncrypt() {
    PartialRsaKeyPair keyPair = new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), RSA_KEY_PAIR.getPublic());
    try {
      RsaKeyring.builder()
        .wrappingKeyPair(keyPair)
        .reEncryptInstructionFile(true)
        .build();
      throw new RuntimeException("Expected failure!");
    } catch (S3EncryptionClientException e) {
      assertTrue(e.getMessage().contains("Materials description must be provided for re-encrypt instruction file!"));
    }
  }
  @Test
  public void testMaterialsDescriptionAesKeyringWithNoReEncrypt() {
    try {
      AesKeyring.builder()
        .wrappingKey(AES_KEY)
        .reEncryptInstructionFile(true)
        .build();
      throw new RuntimeException("Expected fa");
    } catch (S3EncryptionClientException e) {
      assertTrue(e.getMessage().contains("Materials description must be provided for re-encrypt instruction file!"));
    }
  }

}