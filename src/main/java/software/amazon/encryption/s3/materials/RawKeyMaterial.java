// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

/**
 * This class represents raw key material used by keyrings.
 * It contains a materials description and the actual key material.
 *
 * @param <T> the type of key material
 */
public class RawKeyMaterial<T> {

    protected final MaterialsDescription _materialsDescription;
    protected final T _keyMaterial;

    private RawKeyMaterial(Builder<T> builder) {
        this._materialsDescription = builder._materialsDescription;
        this._keyMaterial = builder._keyMaterial;
    }

    /**
     * Protected constructor for subclasses.
     *
     * @param materialsDescription the materials description
     * @param keyMaterial          the key material
     */
    protected RawKeyMaterial(MaterialsDescription materialsDescription, T keyMaterial) {
        this._materialsDescription = materialsDescription;
        this._keyMaterial = keyMaterial;
    }

    /**
     * @return a new builder instance
     */
    public static <T> Builder<T> builder() {
        return new Builder<>();
    }

    /**
     * @return the materials description
     */
    public MaterialsDescription getMaterialsDescription() {
        return _materialsDescription;
    }

    /**
     * @return the key material
     */
    public T getKeyMaterial() {
        return _keyMaterial;
    }

    /**
     * Builder for RawKeyMaterial.
     *
     * @param <T> the type of key material
     */
    public static class Builder<T> {
        private MaterialsDescription _materialsDescription;
        private T _keyMaterial;

        /**
         * Sets the materials description for this raw key material.
         *
         * @param materialsDescription the materials description
         * @return a reference to this object so that method calls can be chained together.
         */
        public Builder<T> materialsDescription(MaterialsDescription materialsDescription) {
            this._materialsDescription = materialsDescription;
            return this;
        }

        /**
         * Sets the key material.
         *
         * @param keyMaterial the key material
         * @return a reference to this object so that method calls can be chained together.
         */
        public Builder<T> keyMaterial(T keyMaterial) {
            this._keyMaterial = keyMaterial;
            return this;
        }

        /**
         * @return the built RawKeyMaterial
         */
        public RawKeyMaterial<T> build() {
            return new RawKeyMaterial<>(this);
        }
    }
}
