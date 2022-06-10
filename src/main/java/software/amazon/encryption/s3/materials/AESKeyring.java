package software.amazon.encryption.s3.materials;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

/**
 * AESKeyring will use an AES key to wrap the data key used to encrypt content.
 */
public class AESKeyring implements Keyring {

    private static final String KEY_ALGORITHM = "AES";
    private static final String KEY_PROVIDER_ID = "AES/GCM";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int NONCE_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BYTES = 16;
    private static final int TAG_LENGTH_BITS = TAG_LENGTH_BYTES * 8;

    private final DataKeyGenerator _dataKeyGenerator;
    private final SecretKey _wrappingKey;

    private AESKeyring(Builder builder) {
        _dataKeyGenerator = builder._dataKeyGenerator;
        _wrappingKey = builder._wrappingKey;
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
            SecureRandom secureRandom = new SecureRandom();

            AlgorithmSuite algorithmSuite = materials.algorithmSuite();
            byte[] nonce = new byte[NONCE_LENGTH_BYTES];
            secureRandom.nextBytes(nonce);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, nonce);

            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, _wrappingKey, gcmParameterSpec, secureRandom);

            // this is the CONTENT encryption, not the wrapping encryption
            cipher.updateAAD(algorithmSuite.cipherName().getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = cipher.doFinal(materials.plaintextDataKey());

            // The encrypted data key is the nonce prepended to the ciphertext
            byte[] encodedBytes = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, encodedBytes, 0, nonce.length);
            System.arraycopy(ciphertext, 0, encodedBytes, nonce.length, ciphertext.length);

            EncryptedDataKey encryptedDataKey = EncryptedDataKey.builder()
                    .keyProviderId(KEY_PROVIDER_ID)
                    .ciphertext(encodedBytes)
                    .build();

            List<EncryptedDataKey> encryptedDataKeys = new ArrayList<>(materials.encryptedDataKeys());
            encryptedDataKeys.add(encryptedDataKey);

            return materials.toBuilder()
                    .encryptedDataKeys(encryptedDataKeys)
                    .build();
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to " + CIPHER_ALGORITHM + " wrap", e);
        }
    }

    @Override
    public DecryptionMaterials onDecrypt(final DecryptionMaterials materials, List<EncryptedDataKey> encryptedDataKeys) {
        if (materials.plaintextDataKey() != null) {
            return materials;
        }

        for (EncryptedDataKey encryptedDataKey : encryptedDataKeys) {
            if (!encryptedDataKey.keyProviderId().equals(KEY_PROVIDER_ID)) {
                continue;
            }

            byte[] encodedBytes = encryptedDataKey.ciphertext();
            byte[] nonce = new byte[NONCE_LENGTH_BYTES];
            byte[] ciphertext = new byte[encodedBytes.length - nonce.length];

            System.arraycopy(encodedBytes, 0, nonce, 0, nonce.length);
            System.arraycopy(encodedBytes, nonce.length, ciphertext, 0, ciphertext.length);


            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, nonce);
            try {
                final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, _wrappingKey, gcmParameterSpec);
                // this is the CONTENT encryption, not the wrapping encryption
                AlgorithmSuite algorithmSuite = materials.algorithmSuite();
                cipher.updateAAD(algorithmSuite.cipherName().getBytes(StandardCharsets.UTF_8));
                byte[] plaintext = cipher.doFinal(ciphertext);

                return materials.toBuilder().plaintextDataKey(plaintext).build();
            } catch (Exception e) {
                throw new S3EncryptionClientException("Unable to " + CIPHER_ALGORITHM + " unwrap", e);
            }
        }

        return materials;
    }

    public static class Builder {
        private DataKeyGenerator _dataKeyGenerator = new DefaultDataKeyGenerator();
        private SecretKey _wrappingKey;

        private Builder() {}

        public Builder wrappingKey(SecretKey wrappingKey) {
            if (!wrappingKey.getAlgorithm().equals(KEY_ALGORITHM)) {
                throw new S3EncryptionClientException("Invalid algorithm '" + wrappingKey.getAlgorithm() + "', expecting " + KEY_ALGORITHM);
            }
            _wrappingKey = wrappingKey;
            return this;
        }

        public Builder dataKeyGenerator(DataKeyGenerator dataKeyGenerator) {
            _dataKeyGenerator = dataKeyGenerator;
            return this;
        }

        public AESKeyring build() {
            return new AESKeyring(this);
        }
    }
}