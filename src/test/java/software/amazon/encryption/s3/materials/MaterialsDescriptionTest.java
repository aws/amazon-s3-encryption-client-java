package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

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
import static org.junit.jupiter.api.Assertions.fail;

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
      .materialsDescription(MaterialsDescription.builder()
        .put("version", "1.0")
        .put("admin", "yes")
        .build())
      .build();
    assertNotNull(aesKeyring);
  }

  @Test
  public void testMaterialsDescriptionRsaKeyring() {
    PartialRsaKeyPair keyPair = new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), RSA_KEY_PAIR.getPublic());
    RsaKeyring rsaKeyring = RsaKeyring.builder()
      .wrappingKeyPair(keyPair)
      .materialsDescription(MaterialsDescription.builder()
        .put("version", "1.0")
        .put("admin", "yes")
        .build())
      .build();
    assertNotNull(rsaKeyring);

  }

}