// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.security.Provider;

public class DefaultCryptoMaterialsManager implements CryptographicMaterialsManager {
    private final Keyring _keyring;
    private final Provider _cryptoProvider;

    private DefaultCryptoMaterialsManager(Builder builder) {
        _keyring = builder._keyring;
        _cryptoProvider = builder._cryptoProvider;
    }

    public static Builder builder() {
        return new Builder();
    }

    public EncryptionMaterials getEncryptionMaterials(EncryptionMaterialsRequest request) {
        EncryptionMaterials materials = EncryptionMaterials.builder()
                .s3Request(request.s3Request())
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .encryptionContext(request.encryptionContext())
                .cryptoProvider(_cryptoProvider)
                .plaintextLength(request.plaintextLength())
                .build();

        return _keyring.onEncrypt(materials);
    }

    public DecryptionMaterials decryptMaterials(DecryptMaterialsRequest request) {
        DecryptionMaterials materials = DecryptionMaterials.builder()
                .s3Request(request.s3Request())
                .algorithmSuite(request.algorithmSuite())
                .encryptionContext(request.encryptionContext())
                .ciphertextLength(request.ciphertextLength())
                .cryptoProvider(_cryptoProvider)
                .build();

        return _keyring.onDecrypt(materials, request.encryptedDataKeys());
    }

    public static class Builder {
        private Keyring _keyring;
        private Provider _cryptoProvider;

        private Builder() {}

        public Builder keyring(Keyring keyring) {
            this._keyring = keyring;
            return this;
        }

        public Builder cryptoProvider(Provider cryptoProvider) {
            this._cryptoProvider = cryptoProvider;
            return this;
        }

        public DefaultCryptoMaterialsManager build() {
            return new DefaultCryptoMaterialsManager(this);
        }
    }
}
