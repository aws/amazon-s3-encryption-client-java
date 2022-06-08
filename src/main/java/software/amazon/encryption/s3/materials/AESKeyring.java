package software.amazon.encryption.s3.materials;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

public class AESKeyring implements Keyring {

    private static final String KEY_ALGORITHM = "AES";
    private static final String KEY_PROVIDER_ID = "AES/GCM";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int NONCE_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BYTES = 16;
    private static final int TAG_LENGTH_BITS = TAG_LENGTH_BYTES * 8;
    private final SecretKey _wrappingKey;

    public AESKeyring(SecretKey wrappingKey) {
        if (!wrappingKey.getAlgorithm().equals(KEY_ALGORITHM)) {
            // TODO: throw?
        }

        _wrappingKey = wrappingKey;
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials materials) {
        // TODO: handle a null plaintext data key

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

            // The encrypted data key is the IV prepended to the ciphertext
            nonce = cipher.getIV();
            byte[] ciphertext = cipher.doFinal(materials.plaintextDataKey());

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
            throw new UnsupportedOperationException("Unable to " + CIPHER_ALGORITHM + " wrap", e);
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
                // TODO: maybe this should fall through?
                throw new UnsupportedOperationException("Unable to " + CIPHER_ALGORITHM + " unwrap", e);
            }
        }

        return materials;
    }
}