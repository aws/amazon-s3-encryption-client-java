// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import javax.crypto.SecretKey;

/**
 * A concrete implementation of RawKeyMaterial for AES keys.
 * This class provides a more convenient way to create key material for AES keyrings
 * without having to specify the generic type parameter.
 */
public class AesKeyMaterial extends RawKeyMaterial<SecretKey> {

    /**
     * Creates a new AesKeyMaterial with the specified materials description and key material.
     *
     * @param materialsDescription the materials description
     * @param keyMaterial the AES key material
     */
    public AesKeyMaterial(MaterialsDescription materialsDescription, SecretKey keyMaterial) {
        super(materialsDescription, keyMaterial);
    }

    /**
     * @return a new builder instance for AesKeyMaterial
     */
    public static Builder aesBuilder() {
        return new Builder();
    }

    /**
     * Builder for AesKeyMaterial.
     */
    public static class Builder {
        private MaterialsDescription _materialsDescription;
        private SecretKey _keyMaterial;

        /**
         * Sets the materials description for this AES key material.
         *
         * @param materialsDescription the materials description
         * @return a reference to this object so that method calls can be chained together.
         */
        public Builder materialsDescription(MaterialsDescription materialsDescription) {
            this._materialsDescription = materialsDescription;
            return this;
        }

        /**
         * Sets the AES key material.
         *
         * @param keyMaterial the AES key material
         * @return a reference to this object so that method calls can be chained together.
         */
        public Builder keyMaterial(SecretKey keyMaterial) {
            this._keyMaterial = keyMaterial;
            return this;
        }

        /**
         * @return the built AesKeyMaterial
         */
        public AesKeyMaterial build() {
            return new AesKeyMaterial(_materialsDescription, _keyMaterial);
        }
    }
}
