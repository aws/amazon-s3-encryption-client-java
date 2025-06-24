package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.Test;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class MaterialsDescriptionTest {

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

}