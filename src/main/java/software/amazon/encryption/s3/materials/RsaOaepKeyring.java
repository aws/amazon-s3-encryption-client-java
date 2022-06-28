package software.amazon.encryption.s3.materials;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.encryption.s3.S3EncryptionClientException;

/**
 * RsaOaepKeyring will use an RSA public key to wrap the data key used to encrypt content.
 */
public class RsaOaepKeyring implements Keyring {

    private static final String KEY_ALGORITHM = "RSA";
    private static final String KEY_PROVIDER_ID = "RSA-OAEP-SHA1";
    private static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPPadding";
    private static final String DIGEST_NAME = "SHA-1";
    private static final String MGF_NAME = "MGF1";
    private static final MGF1ParameterSpec MGF_PARAMETER_SPEC = new MGF1ParameterSpec(DIGEST_NAME);
    private static final OAEPParameterSpec OAEP_PARAMETER_SPEC =
            new OAEPParameterSpec(DIGEST_NAME, MGF_NAME, MGF_PARAMETER_SPEC, PSpecified.DEFAULT);

    private final KeyPair _wrappingKeyPair;
    private final SecureRandom _secureRandom;
    private final DataKeyGenerator _dataKeyGenerator;

    private RsaOaepKeyring(Builder builder) {
        _wrappingKeyPair = builder._wrappingKeyPair;
        _secureRandom = builder._secureRandom;
        _dataKeyGenerator = builder._dataKeyGenerator;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials materials) {
        if (materials.plaintextDataKey() == null) {
            SecretKey dataKey = _dataKeyGenerator.generateDataKey(materials.algorithmSuite());
            materials = materials.toBuilder()
                    .plaintextDataKey(dataKey.getEncoded())
                    .build();
        }

        try {
            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.WRAP_MODE, _wrappingKeyPair.getPublic(), OAEP_PARAMETER_SPEC, _secureRandom);

            // Create a pseudo-data key with the content encryption appended to the data key
            byte[] dataKey = materials.plaintextDataKey();
            byte[] dataCipherName = materials.algorithmSuite().cipherName().getBytes(StandardCharsets.UTF_8);
            byte[] pseudoDataKey = new byte[1 + dataKey.length + dataCipherName.length];

            pseudoDataKey[0] = (byte)dataKey.length;
            System.arraycopy(dataKey, 0, pseudoDataKey, 1, dataKey.length);
            System.arraycopy(dataCipherName, 0, pseudoDataKey, 1 + dataKey.length, dataCipherName.length);

            byte[] ciphertext = cipher.wrap(new SecretKeySpec(pseudoDataKey, materials.algorithmSuite().dataKeyAlgorithm()));

            EncryptedDataKey encryptedDataKey = EncryptedDataKey.builder()
                    .keyProviderId(KEY_PROVIDER_ID)
                    .ciphertext(ciphertext)
                    .build();

            List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>(materials.encryptedDataKeys());
            encryptedDataKeys.add(encryptedDataKey);

            return materials.toBuilder()
                    .encryptedDataKeys(encryptedDataKeys)
                    .build();
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to " + KEY_PROVIDER_ID + " wrap", e);
        }
    }

    @Override
    public DecryptionMaterials onDecrypt(final DecryptionMaterials materials, List<EncryptedDataKey> encryptedDataKeys) {
        if (materials.plaintextDataKey() != null) {
            throw new S3EncryptionClientException("Decryption materials already contains a plaintext data key.");
        }

        for (EncryptedDataKey encryptedDataKey : encryptedDataKeys) {
            if (!encryptedDataKey.keyProviderId().equals(KEY_PROVIDER_ID)) {
                continue;
            }

            try {
                final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
                cipher.init(Cipher.UNWRAP_MODE, _wrappingKeyPair.getPrivate(), OAEP_PARAMETER_SPEC, _secureRandom);

                String dataKeyAlgorithm = materials.algorithmSuite().dataKeyAlgorithm();
                Key pseudoDataKey = cipher.unwrap(encryptedDataKey.ciphertext(), dataKeyAlgorithm, Cipher.SECRET_KEY);

                byte[] plaintext = parsePseudoDataKey(materials, pseudoDataKey.getEncoded());

                return materials.toBuilder().plaintextDataKey(plaintext).build();
            } catch (Exception e) {
                throw new S3EncryptionClientException("Unable to " + KEY_PROVIDER_ID + " unwrap", e);
            }
        }

        return materials;
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

    public static class Builder {
        private KeyPair _wrappingKeyPair;
        private SecureRandom _secureRandom = new SecureRandom();
        private DataKeyGenerator _dataKeyGenerator = new DefaultDataKeyGenerator();

        private Builder() {}

        public Builder wrappingKeyPair(KeyPair wrappingKeyPair) {
            if (!wrappingKeyPair.getPublic().getAlgorithm().equals(KEY_ALGORITHM)) {
                throw new S3EncryptionClientException("Invalid algorithm '" + wrappingKeyPair.getPublic().getAlgorithm() + "', expecting " + KEY_ALGORITHM);
            }
            _wrappingKeyPair = wrappingKeyPair;
            return this;
        }

        public Builder secureRandom(SecureRandom secureRandom) {
            _secureRandom = secureRandom;
            return this;
        }

        public Builder dataKeyGenerator(DataKeyGenerator dataKeyGenerator) {
            _dataKeyGenerator = dataKeyGenerator;
            return this;
        }

        public RsaOaepKeyring build() {
            return new RsaOaepKeyring(this);
        }
    }
}
