package software.amazon.encryption.s3.materials;

import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

public class DefaultCryptoMaterialsManager implements CryptographicMaterialsManager {
    private final Keyring _keyring;


    private DefaultCryptoMaterialsManager(Builder builder) {
        _keyring = builder._keyring;
    }

    public static Builder builder() {
        return new Builder();
    }

    public EncryptionMaterials getEncryptionMaterials(EncryptionMaterialsRequest request) {
        EncryptionMaterials materials = EncryptionMaterials.builder()
                .s3Request(request.s3Request())
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .encryptionContext(request.encryptionContext())
                .build();

        return _keyring.onEncrypt(materials);
    }

    public DecryptionMaterials decryptMaterials(DecryptMaterialsRequest request) {
        DecryptionMaterials materials = DecryptionMaterials.builder()
                .s3Request(request.s3Request())
                .algorithmSuite(request.algorithmSuite())
                .encryptionContext(request.encryptionContext())
                .build();

        return _keyring.onDecrypt(materials, request.encryptedDataKeys());
    }

    public static class Builder {
        private Keyring _keyring;

        private Builder() {}

        public Builder keyring(Keyring keyring) {
            this._keyring = keyring;
            return this;
        }

        public DefaultCryptoMaterialsManager build() {
            return new DefaultCryptoMaterialsManager(this);
        }
    }
}
