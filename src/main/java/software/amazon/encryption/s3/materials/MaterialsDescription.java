// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.encryption.s3.materials;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * This class is used to provide key-value pairs that describe the key material used with the Keyring, specifically for AES and RSA Keyrings.
 * This will be useful during the re-encryption of instruction file.
 * The stored Materials Description is immutable once created.
 */
public class MaterialsDescription implements Map<String, String> {
    private final Map<String, String> materialsDescription;

    private MaterialsDescription(Builder builder) {
        this.materialsDescription = Collections.unmodifiableMap(new HashMap<>(builder.materialsDescription));
    }
    public static Builder builder() {
        return new Builder();
    }
    public Map<String, String> getMaterialsDescription() {
      return this.materialsDescription;
    }

  @Override
  public int size() {
    return materialsDescription.size();
  }

  @Override
  public boolean isEmpty() {
    return materialsDescription.isEmpty();
  }

  @Override
  public boolean containsKey(Object key) {
    return materialsDescription.containsKey(key);
  }

  @Override
  public boolean containsValue(Object value) {
    return materialsDescription.containsValue(value);
  }

  @Override
  public String get(Object key) {
    return materialsDescription.get(key);
  }

  @Override
  public String put(String key, String value) {
    return materialsDescription.put(key, value);
  }

  @Override
  public String remove(Object key) {
    return materialsDescription.remove(key);
  }

  @Override
  public void putAll(Map<? extends String, ? extends String> m) {
      materialsDescription.putAll(m);
  }

  @Override
  public void clear() {
      materialsDescription.clear();
  }

  @Override
  public Set<String> keySet() {
     return materialsDescription.keySet();
  }

  @Override
  public Collection<String> values() {
      return materialsDescription.values();
  }

  @Override
  public Set<Entry<String, String>> entrySet() {
      return materialsDescription.entrySet();
  }


  public static class Builder {
        private final Map<String, String> materialsDescription = new HashMap<>();
        public Builder put(String key, String value) {
            if (key == null || value == null) {
                throw new IllegalArgumentException("Key and value must not be null");
            }
            materialsDescription.put(key, value);
            return this;
        }
        public Builder putAll(Map<String, String> description) {
          if (description == null) {
            throw new IllegalArgumentException("Description must not be null");
          }
          for (Map.Entry<String, String> entry : description.entrySet()) {
            put(entry.getKey(), entry.getValue());
          }
          return this;
        }
        public MaterialsDescription build() {
          return new MaterialsDescription(this);
        }
    }
}