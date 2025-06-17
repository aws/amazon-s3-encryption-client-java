// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.encryption.s3.materials;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class MaterialsDescription {
    private final Map<String, String> materialsDescription;

    private MaterialsDescription(Builder builder) {
        this.materialsDescription = Collections.unmodifiableMap(new HashMap<>(builder.materialsDescription));
    }
    public static Builder builder() {
        return new Builder();
    }
    public Map<String, String> getDescription() {
      return this.materialsDescription;
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