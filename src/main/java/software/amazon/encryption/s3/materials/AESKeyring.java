package software.amazon.encryption.s3.materials;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class AESKeyring implements Keyring {

    private static final String KEY_PROVIDER_ID = "AES/GCM";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_IN_BYTES = 12;
    private static final int TAG_LENGTH_IN_BYTES = 16;
    private static final int TAG_LENGTH_IN_BITS = TAG_LENGTH_IN_BYTES * 8;
    private final SecretKey _wrappingKey;

    public AESKeyring(SecretKey wrappingKey) {
        if (!wrappingKey.getAlgorithm().equals("AES")) {
            // TODO: throw?
        }

        _wrappingKey = wrappingKey;
    }

    @Override
    public EncryptionMaterials onEncrypt(EncryptionMaterials materials) {
        // TODO: handle a null plaintext data key

        try {
            SecureRandom secureRandom = new SecureRandom();

            byte[] iv = new byte[IV_LENGTH_IN_BYTES];
            secureRandom.nextBytes(iv);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_IN_BITS, iv);

            final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, _wrappingKey, gcmParameterSpec, secureRandom);

            // this is the CONTENT encryption, not the wrapping encryption
            // TODO: get this from encryption context or preferably algorithm suite
            cipher.updateAAD("AES/GCM/NoPadding".getBytes(StandardCharsets.UTF_8));

            // The encrypted data key is the IV prepended to the ciphertext
            iv = cipher.getIV();
            byte[] ciphertext = cipher.doFinal(materials.plaintextDataKey());

            byte[] encodedBytes = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, encodedBytes, 0, iv.length);
            System.arraycopy(ciphertext, 0, encodedBytes, iv.length, ciphertext.length);

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
            throw new UnsupportedOperationException("Unable to AES/GCM/NoPadding wrap", e);
        }
    }

    @Override
    public DecryptionMaterials onDecrypt(final DecryptionMaterials materials, List<EncryptedDataKey> encryptedDataKeys) {
        /*
        ByteBuffer encryptedCekBuff = ByteBuffer.wrap(encryptedCek);
        // Split the IV from the front of the ciphertext
        byte[] iv = new byte[IV_LENGTH_IN_BYTES];
        byte[] taggedCek = new byte[encryptedCek.length - IV_LENGTH_IN_BYTES];
        encryptedCekBuff.get(iv);
        encryptedCekBuff.get(taggedCek);

        Cipher cipher = this.cipherProvider.createCipher();
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_IN_BITS, iv);
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            cipher.updateAAD(this.cekAlgorithm.getBytes(StandardCharsets.UTF_8));
            return cipher.doFinal(taggedCek);
        } catch (Exception e) {
            throw failure(e, "An exception was thrown when attempting to decrypt the Content Encryption Key");
        }
         */
        if (materials.plaintextDataKey() != null) {
            return materials;
        }

        for (EncryptedDataKey encryptedDataKey : encryptedDataKeys) {
            if (!encryptedDataKey.keyProviderId().equals(KEY_PROVIDER_ID)) {
                continue;
            }

            byte[] encodedBytes = encryptedDataKey.ciphertext();
            byte[] iv = new byte[IV_LENGTH_IN_BYTES];
            byte[] ciphertext = new byte[encodedBytes.length - iv.length];

            System.arraycopy(encodedBytes, 0, iv, 0, iv.length);
            System.arraycopy(encodedBytes, iv.length, ciphertext, 0, ciphertext.length);

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_IN_BITS, iv);
            try {
                final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, _wrappingKey, gcmParameterSpec);
                // this is the CONTENT encryption, not the wrapping encryption
                // TODO: get this from encryption context or preferably algorithm suite
                cipher.updateAAD("AES/GCM/NoPadding".getBytes(StandardCharsets.UTF_8));
                byte[] plaintext = cipher.doFinal(ciphertext);

                return materials.toBuilder().plaintextDataKey(plaintext).build();
            } catch (Exception e) {
                // TODO: maybe this should fall through?
                throw new UnsupportedOperationException("Unable to AES/GCM/NoPadding unwrap", e);
            }
        }

        return materials;
    }
}