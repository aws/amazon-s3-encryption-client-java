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
 * AesKeyring is a legacy, decrypt-only keyring and will use an AES key to decrypt the data key
 * used to encrypt content.
 */
public class AesKeyring implements Keyring, LegacyKeyring {

    private static final String KEY_ALGORITHM = "AES";
    private static final String KEY_PROVIDER_ID = "AES";
    private static final String CIPHER_ALGORITHM = "AES";

    private final SecretKey _wrappingKey;

    private AesKeyring(Builder builder) {
        _wrappingKey = builder._wrappingKey;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials materials) {
        throw new S3EncryptionClientException("Encrypt not supported for " + KEY_PROVIDER_ID);
    }

    @Override
    public DecryptionMaterials onDecrypt(DecryptionMaterials materials, List<EncryptedDataKey> encryptedDataKeys) {
        if (materials.plaintextDataKey() != null) {
            throw new S3EncryptionClientException("Decryption materials already contains a plaintext data key.");
        }

        for (EncryptedDataKey encryptedDataKey : encryptedDataKeys) {
            if (!encryptedDataKey.keyProviderId().equals(KEY_PROVIDER_ID)) {
                continue;
            }

            try {
                final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, _wrappingKey);

                byte[] plaintextKey = cipher.doFinal(encryptedDataKey.ciphertext());

                return materials.toBuilder().plaintextDataKey(plaintextKey).build();
            } catch (Exception e) {
                throw new S3EncryptionClientException("Unable to " + KEY_PROVIDER_ID + " unwrap", e);
            }
        }

        return materials;
    }

    public static class Builder {
        private SecretKey _wrappingKey;

        private Builder() {}

        public Builder wrappingKey(SecretKey wrappingKey) {
            if (!wrappingKey.getAlgorithm().equals(KEY_ALGORITHM)) {
                throw new S3EncryptionClientException("Invalid algorithm '" + wrappingKey.getAlgorithm() + "', expecting " + KEY_ALGORITHM);
            }
            _wrappingKey = wrappingKey;
            return this;
        }

        public AesKeyring build() {
            return new AesKeyring(this);
        }
    }
}