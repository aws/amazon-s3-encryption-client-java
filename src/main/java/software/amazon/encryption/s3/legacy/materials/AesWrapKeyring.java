package software.amazon.encryption.s3.legacy.materials;

import java.security.Key;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.Keyring;

/**
 * AesWrapKeyring is a legacy, decrypt-only keyring and will use an AES key to unwrap the data key
 * used to encrypt content.
 */
public class AesWrapKeyring implements Keyring {

    private static final String KEY_ALGORITHM = "AES";
    private static final String KEY_PROVIDER_ID = "AESWrap";
    private static final String CIPHER_ALGORITHM = "AESWrap";

    private final SecretKey _wrappingKey;
    private final Keyring _nonLegacyKeyring;

    private AesWrapKeyring(Builder builder) {
        _wrappingKey = builder._wrappingKey;
        _nonLegacyKeyring = builder._nonLegacyKeyring;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials materials) {
        return _nonLegacyKeyring.onEncrypt(materials);
    }

    @Override
    public DecryptionMaterials onDecrypt(DecryptionMaterials materials, List<EncryptedDataKey> encryptedDataKeys) {
        materials = _nonLegacyKeyring.onDecrypt(materials, encryptedDataKeys);

        if (materials.plaintextDataKey() != null) {
            return materials;
        }

        for (EncryptedDataKey encryptedDataKey : encryptedDataKeys) {
            if (!encryptedDataKey.keyProviderId().equals(KEY_PROVIDER_ID)) {
                continue;
            }

            try {
                final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
                cipher.init(Cipher.UNWRAP_MODE, _wrappingKey);

                Key plaintextKey = cipher.unwrap(encryptedDataKey.ciphertext(), CIPHER_ALGORITHM, Cipher.SECRET_KEY);

                return materials.toBuilder().plaintextDataKey(plaintextKey.getEncoded()).build();
            } catch (Exception e) {
                throw new S3EncryptionClientException("Unable to " + KEY_PROVIDER_ID + " unwrap", e);
            }
        }

        return materials;
    }

    public static class Builder {
        private SecretKey _wrappingKey;
        private Keyring _nonLegacyKeyring;

        private Builder() {}

        public Builder wrappingKey(SecretKey wrappingKey) {
            if (!wrappingKey.getAlgorithm().equals(KEY_ALGORITHM)) {
                throw new S3EncryptionClientException("Invalid algorithm '" + wrappingKey.getAlgorithm() + "', expecting " + KEY_ALGORITHM);
            }
            _wrappingKey = wrappingKey;
            return this;
        }

        public Builder nonLegacyKeyring(Keyring nonLegacyKeyring) {
            _nonLegacyKeyring = nonLegacyKeyring;
            return this;
        }

        public AesWrapKeyring build() {
            if (_nonLegacyKeyring == null) {
                // TODO: should we warn or throw an exception if no encryption method is supported?
            }
            return new AesWrapKeyring(this);
        }
    }
}