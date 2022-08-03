package software.amazon.encryption.s3.legacy.materials;


import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.Keyring;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyPair;
import java.util.List;

/**
 * RsaEcbKeyring is a legacy, decrypt-only keyring and will use an RSA Public key to unwrap the data key
 * used to encrypt content.
 */

public class RsaEcbKeyring implements Keyring, LegacyKeyring {

    private static final String KEY_ALGORITHM = "RSA";
    private static final String KEY_PROVIDER_ID = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private final KeyPair _wrappingKeyPair;

    private RsaEcbKeyring(RsaEcbKeyring.Builder builder) {
        _wrappingKeyPair = builder._wrappingKeyPair;
    }

    public static RsaEcbKeyring.Builder builder() {
        return new RsaEcbKeyring.Builder();
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
                cipher.init(Cipher.UNWRAP_MODE, _wrappingKeyPair.getPrivate());

                Key plaintextKey = cipher.unwrap(encryptedDataKey.ciphertext(), CIPHER_ALGORITHM, Cipher.SECRET_KEY);

                return materials.toBuilder().plaintextDataKey(plaintextKey.getEncoded()).build();
            } catch (Exception e) {
                throw new S3EncryptionClientException("Unable to " + KEY_PROVIDER_ID + " unwrap", e);
            }
        }

        return materials;
    }

    public static class Builder {
        private KeyPair _wrappingKeyPair;

        private Builder() {}

        public RsaEcbKeyring.Builder wrappingKeyPair(KeyPair wrappingKeyPair) {
            if (!wrappingKeyPair.getPublic().getAlgorithm().equals(KEY_ALGORITHM)) {
                throw new S3EncryptionClientException("Invalid algorithm '" + wrappingKeyPair.getPublic().getAlgorithm() + "', expecting " + KEY_ALGORITHM);
            }
            _wrappingKeyPair = wrappingKeyPair;
            return this;
        }

        public RsaEcbKeyring build() {
            return new RsaEcbKeyring(this);
        }
    }
}


