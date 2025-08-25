// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

/**
 * A concrete implementation of RawKeyMaterial for RSA keys.
 * This class provides a more convenient way to create key material for RSA keyrings
 * without having to specify the generic type parameter.
 */
public class RsaKeyMaterial extends RawKeyMaterial<PartialRsaKeyPair> {

    /**
     * Creates a new RsaKeyMaterial with the specified materials description and key material.
     *
     * @param materialsDescription the materials description
     * @param keyMaterial the RSA key material
     */
    public RsaKeyMaterial(MaterialsDescription materialsDescription, PartialRsaKeyPair keyMaterial) {
        super(materialsDescription, keyMaterial);
    }

    /**
     * @return a new builder instance for RsaKeyMaterial
     */
    public static Builder rsaBuilder() {
        return new Builder();
    }

    /**
     * Builder for RsaKeyMaterial.
     */
    public static class Builder {
        private MaterialsDescription _materialsDescription;
        private PartialRsaKeyPair _keyMaterial;

        /**
         * Sets the materials description for this RSA key material.
         *
         * @param materialsDescription the materials description
         * @return a reference to this object so that method calls can be chained together.
         */
        public Builder materialsDescription(MaterialsDescription materialsDescription) {
            this._materialsDescription = materialsDescription;
            return this;
        }

        /**
         * Sets the RSA key material.
         *
         * @param keyMaterial the RSA key material
         * @return a reference to this object so that method calls can be chained together.
         */
        public Builder keyMaterial(PartialRsaKeyPair keyMaterial) {
            this._keyMaterial = keyMaterial;
            return this;
        }

        /**
         * @return the built RsaKeyMaterial
         */
        public RsaKeyMaterial build() {
            return new RsaKeyMaterial(_materialsDescription, _keyMaterial);
        }
    }
}
