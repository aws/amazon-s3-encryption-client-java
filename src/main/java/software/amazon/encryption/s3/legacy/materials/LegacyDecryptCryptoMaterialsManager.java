package software.amazon.encryption.s3.legacy.materials;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DecryptMaterialsRequest;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterialsRequest;
import software.amazon.encryption.s3.materials.Keyring;

/**
 * This class supports legacy decrypt as well as non-legacy encrypt and decrypt.
 *
 * It will only use the non-legacy keyring for encrypt.
 * For decrypt, it will attempt to use the legacy keyring first.
 * If the legacy keyring fails to decrypt, the non-legacy keyring will be used.
 */
public class LegacyDecryptCryptoMaterialsManager implements CryptographicMaterialsManager {
    private final Keyring _keyring;
    private LegacyKeyring _legacyKeyring;

    private LegacyDecryptCryptoMaterialsManager(Builder builder) {
        _keyring = builder._keyring;
        _legacyKeyring = builder._legacyKeyring;
    }

    public static Builder builder() {
        return new Builder();
    }

    public EncryptionMaterials getEncryptionMaterials(EncryptionMaterialsRequest request) {
        EncryptionMaterials materials = EncryptionMaterials.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .encryptionContext(request.encryptionContext())
                .build();

        return _keyring.onEncrypt(materials);
    }

    public DecryptionMaterials decryptMaterials(DecryptMaterialsRequest request) {
        DecryptionMaterials materials = DecryptionMaterials.builder()
                .algorithmSuite(request.algorithmSuite())
                .encryptionContext(request.encryptionContext())
                .build();

        materials = _legacyKeyring.onDecrypt(materials, request.encryptedDataKeys());
        if (materials.plaintextDataKey() != null) {
            // Have a legacy-encrypted data key
            // TODO: warn here?
            return materials;
        }

        return _keyring.onDecrypt(materials, request.encryptedDataKeys());
    }

    public static class Builder {
        private Keyring _keyring;
        private LegacyKeyring _legacyKeyring;

        private Builder() {}

        public Builder keyring(Keyring keyring) {
            if (keyring instanceof LegacyKeyring) {
                throw new S3EncryptionClientException("Cannot use a legacy keyring here, please configure and use an active keyring here");
            }
            this._keyring = keyring;
            return this;
        }

        public Builder legacyKeyring(LegacyKeyring legacyKeyring) {
            this._legacyKeyring = legacyKeyring;
            return this;
        }

        public LegacyDecryptCryptoMaterialsManager build() {
            // TODO: warn if both keyrings are not set
            return new LegacyDecryptCryptoMaterialsManager(this);
        }
    }
}
