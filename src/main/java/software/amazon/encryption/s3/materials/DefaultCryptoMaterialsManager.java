package software.amazon.encryption.s3.materials;

import java.security.SecureRandom;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

public class DefaultCryptoMaterialsManager implements CryptographicMaterialsManager {
    private final Keyring _keyring;
    private final SecureRandom _secureRandom;

    private DefaultCryptoMaterialsManager(Builder builder) {
        _keyring = builder._keyring;
        _secureRandom = builder._secureRandom;
    }

    public static Builder builder() {
        return new Builder();
    }

    public SecureRandom getSecureRandom() {
        return _secureRandom;
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
                .ciphertextLength(request.ciphertextLength())
                .build();

        return _keyring.onDecrypt(materials, request.encryptedDataKeys());
    }

    public static class Builder {
        private Keyring _keyring;
        private SecureRandom _secureRandom;

        private Builder() {}

        public Builder keyring(Keyring keyring) {
            this._keyring = keyring;
            return this;
        }

        public Builder secureRandom(SecureRandom secureRandom) {
            this._secureRandom = secureRandom;
            return this;
        }

        public DefaultCryptoMaterialsManager build() {
            return new DefaultCryptoMaterialsManager(this);
        }
    }
}
