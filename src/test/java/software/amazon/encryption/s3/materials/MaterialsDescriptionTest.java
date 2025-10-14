package software.amazon.encryption.s3.materials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

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
    MaterialsDescription materialsDescription = MaterialsDescription
      .builder()
      .put("version", "1.0")
      .build();
    assertEquals(
      "1.0",
      materialsDescription.getMaterialsDescription().get("version")
    );
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
    MaterialsDescription materialsDescription = MaterialsDescription
      .builder()
      .putAll(description)
      .build();
    assertEquals(2, materialsDescription.getMaterialsDescription().size());
    assertTrue(
      materialsDescription.getMaterialsDescription().containsKey("version")
    );
    assertTrue(
      materialsDescription.getMaterialsDescription().containsKey("next-version")
    );
    assertEquals(
      "1.0",
      materialsDescription.getMaterialsDescription().get("version")
    );
    assertEquals(
      "2.0",
      materialsDescription.getMaterialsDescription().get("next-version")
    );
  }

  @Test
  public void testMaterialsDescriptionAesKeyring() {
    AesKeyring aesKeyring = AesKeyring
      .builder()
      .wrappingKey(AES_KEY)
      .materialsDescription(
        MaterialsDescription
          .builder()
          .put("version", "1.0")
          .put("admin", "yes")
          .build()
      )
      .build();
    assertNotNull(aesKeyring);
  }

  @Test
  public void testMaterialsDescriptionRsaKeyring() {
    PartialRsaKeyPair keyPair = new PartialRsaKeyPair(
      RSA_KEY_PAIR.getPrivate(),
      RSA_KEY_PAIR.getPublic()
    );
    RsaKeyring rsaKeyring = RsaKeyring
      .builder()
      .wrappingKeyPair(keyPair)
      .materialsDescription(
        MaterialsDescription
          .builder()
          .put("version", "1.0")
          .put("admin", "yes")
          .build()
      )
      .build();
    assertNotNull(rsaKeyring);
  }

  @Test
  public void testEquals() {
    // Create two identical MaterialsDescription objects
    MaterialsDescription desc1 = MaterialsDescription.builder()
        .put("key1", "value1")
        .put("key2", "value2")
        .build();

    MaterialsDescription desc2 = MaterialsDescription.builder()
        .put("key1", "value1")
        .put("key2", "value2")
        .build();

    // Create a MaterialsDescription with different values
    MaterialsDescription desc3 = MaterialsDescription.builder()
        .put("key1", "value1")
        .put("key2", "different")
        .build();

    // Create a MaterialsDescription with different keys
    MaterialsDescription desc4 = MaterialsDescription.builder()
        .put("key1", "value1")
        .put("different", "value2")
        .build();

    // Create a MaterialsDescription with different number of entries
    MaterialsDescription desc5 = MaterialsDescription.builder()
        .put("key1", "value1")
        .build();

    // Test reflexivity
    assertEquals(desc1, desc1);

    // Test symmetry
    assertEquals(desc1, desc2);
    assertEquals(desc2, desc1);

    // Test with different values
    assertNotEquals(desc1, desc3);

    // Test with different keys
    assertNotEquals(desc1, desc4);

    // Test with different number of entries
    assertNotEquals(desc1, desc5);

    // Test with null
    assertNotEquals(desc1, null);

    // Test with different type
    assertNotEquals(desc1, "not a MaterialsDescription");

    // Test hashCode
    assertEquals(desc1.hashCode(), desc2.hashCode());
  }
}
