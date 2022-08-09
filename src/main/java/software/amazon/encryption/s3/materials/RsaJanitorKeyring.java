package software.amazon.encryption.s3.materials;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.encryption.s3.S3EncryptionClientException;

/**
 * RsaOaepKeyring will use an RSA public key to wrap the data key used to encrypt content.
 */
public class RsaJanitorKeyring extends S3JanitorKeyring {

    private static final String KEY_ALGORITHM = "RSA";

    private static final DecryptDataKeyStrategy RSA_ECB = new DecryptDataKeyStrategy() {
        private static final String KEY_PROVIDER_ID = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
        private static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

        @Override
        public boolean isLegacy() {
            return true;
        }

        @Override
        public String keyProviderId() {
            return KEY_PROVIDER_ID;
        }

        @Override
        public byte[] decryptDataKey(Key unwrappingKey, DecryptionMaterials materials, EncryptedDataKey encryptedDataKey) throws GeneralSecurityException {
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.UNWRAP_MODE, unwrappingKey);

            Key plaintextKey = cipher.unwrap(encryptedDataKey.ciphertext(), CIPHER_ALGORITHM, Cipher.SECRET_KEY);

            return plaintextKey.getEncoded();
        }
    };

    private static final DataKeyStrategy RSA_OAEP = new DataKeyStrategy() {

        private static final String KEY_PROVIDER_ID = "RSA-OAEP-SHA1";
        private static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPPadding";
        private static final String DIGEST_NAME = "SHA-1";
        private static final String MGF_NAME = "MGF1";

        // Java 8 doesn't support static class fields in inner classes
        private final MGF1ParameterSpec MGF_PARAMETER_SPEC = new MGF1ParameterSpec(DIGEST_NAME);
        private final OAEPParameterSpec OAEP_PARAMETER_SPEC =
                new OAEPParameterSpec(DIGEST_NAME, MGF_NAME, MGF_PARAMETER_SPEC, PSpecified.DEFAULT);

        @Override
        public boolean isLegacy() {
            return false;
        }

        @Override
        public String keyProviderId() {
            return KEY_PROVIDER_ID;
        }

        @Override
        public byte[] encryptDataKey(SecureRandom secureRandom, Key wrappingKey,
                EncryptionMaterials materials) throws GeneralSecurityException {
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.WRAP_MODE, wrappingKey, OAEP_PARAMETER_SPEC, secureRandom);

            // Create a pseudo-data key with the content encryption appended to the data key
            byte[] dataKey = materials.plaintextDataKey();
            byte[] dataCipherName = materials.algorithmSuite().cipherName().getBytes(
                    StandardCharsets.UTF_8);
            byte[] pseudoDataKey = new byte[1 + dataKey.length + dataCipherName.length];

            pseudoDataKey[0] = (byte)dataKey.length;
            System.arraycopy(dataKey, 0, pseudoDataKey, 1, dataKey.length);
            System.arraycopy(dataCipherName, 0, pseudoDataKey, 1 + dataKey.length, dataCipherName.length);

            byte[] ciphertext = cipher.wrap(new SecretKeySpec(pseudoDataKey, materials.algorithmSuite().dataKeyAlgorithm()));
            return ciphertext;
        }

        @Override
        public byte[] decryptDataKey(Key unwrappingKey, DecryptionMaterials materials, EncryptedDataKey encryptedDataKey) throws GeneralSecurityException {
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.UNWRAP_MODE, unwrappingKey, OAEP_PARAMETER_SPEC);

            String dataKeyAlgorithm = materials.algorithmSuite().dataKeyAlgorithm();
            Key pseudoDataKey = cipher.unwrap(encryptedDataKey.ciphertext(), dataKeyAlgorithm, Cipher.SECRET_KEY);

            return parsePseudoDataKey(materials, pseudoDataKey.getEncoded());
        }

        private byte[] parsePseudoDataKey(DecryptionMaterials materials, byte[] pseudoDataKey) {
            int dataKeyLengthBytes = pseudoDataKey[0];
            if (!(dataKeyLengthBytes == 16 || dataKeyLengthBytes == 24 || dataKeyLengthBytes == 32)) {
                throw new S3EncryptionClientException("Invalid key length (" + dataKeyLengthBytes + ") in encrypted data key");
            }

            int dataCipherNameLength = pseudoDataKey.length - dataKeyLengthBytes - 1;
            if (dataCipherNameLength <= 0) {
                throw new S3EncryptionClientException("Invalid data cipher name length (" + dataCipherNameLength + ") in encrypted data key");
            }

            byte[] dataKey = new byte[dataKeyLengthBytes];
            byte[] dataCipherName = new byte[dataCipherNameLength];
            System.arraycopy(pseudoDataKey, 1, dataKey, 0, dataKeyLengthBytes);
            System.arraycopy(pseudoDataKey, 1 + dataKeyLengthBytes, dataCipherName, 0, dataCipherNameLength);

            byte[] expectedDataCipherName = materials.algorithmSuite().cipherName().getBytes(StandardCharsets.UTF_8);
            if (!Arrays.equals(expectedDataCipherName, dataCipherName)) {
                throw new S3EncryptionClientException("The data cipher does not match the data cipher used for encryption. The object may be altered or corrupted");
            }

            return dataKey;
        }
    };

    private static final Map<String, DecryptDataKeyStrategy> DECRYPT_STRATEGIES = new HashMap<>();
    static {
        DECRYPT_STRATEGIES.put(RSA_ECB.keyProviderId(), RSA_ECB);
        DECRYPT_STRATEGIES.put(RSA_OAEP.keyProviderId(), RSA_OAEP);
    }

    private final KeyPair _wrappingKeyPair;

    private RsaJanitorKeyring(Builder builder) {
        super(builder);
        _wrappingKeyPair = builder._wrappingKeyPair;
    }

    public static Builder builder() {
        return new Builder();
    }


    @Override
    protected EncryptDataKeyStrategy encryptStrategy() {
        return RSA_OAEP;
    }

    @Override
    protected Key wrappingKey() {
        return _wrappingKeyPair.getPublic();
    }

    @Override
    protected Map<String, DecryptDataKeyStrategy> decryptStrategies() {
        return DECRYPT_STRATEGIES;
    }

    @Override
    protected Key unwrappingKey() {
        return _wrappingKeyPair.getPrivate();
    }

    public static class Builder extends S3JanitorKeyring.Builder<S3JanitorKeyring> {
        private KeyPair _wrappingKeyPair;

        private Builder() {
            super();
        }

        public Builder wrappingKeyPair(KeyPair wrappingKeyPair) {
            if (!wrappingKeyPair.getPublic().getAlgorithm().equals(KEY_ALGORITHM)) {
                throw new S3EncryptionClientException("Invalid algorithm '" + wrappingKeyPair.getPublic().getAlgorithm() + "', expecting " + KEY_ALGORITHM);
            }
            _wrappingKeyPair = wrappingKeyPair;
            return this;
        }

        public RsaJanitorKeyring build() {
            return new RsaJanitorKeyring(this);
        }
    }

}
