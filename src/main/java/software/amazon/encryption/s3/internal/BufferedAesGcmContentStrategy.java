package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

/**
 * This class will encrypt data according to the algorithm suite constants
 */
public class BufferedAesGcmContentStrategy implements ContentEncryptionStrategy, ContentDecryptionStrategy {

    // 64MiB ought to be enough for most usecases
    private final long BUFFERED_MAX_CONTENT_LENGTH_MiB = 64;
    private final long BUFFERED_MAX_CONTENT_LENGTH_BYTES = 1024 * 1024 * BUFFERED_MAX_CONTENT_LENGTH_MiB;

    final private SecureRandom _secureRandom;

    private BufferedAesGcmContentStrategy(Builder builder) {
        this._secureRandom = builder._secureRandom;
    }

    public static Builder builder() { return new Builder(); }

    @Override
    public EncryptedContent encryptContent(EncryptionMaterials materials, byte[] content) {
        final AlgorithmSuite algorithmSuite = materials.algorithmSuite();

        final byte[] nonce = new byte[algorithmSuite.nonceLengthBytes()];
        _secureRandom.nextBytes(nonce);

        final String cipherName = algorithmSuite.cipherName();
        try {
            final Cipher cipher = Cipher.getInstance(cipherName);

            cipher.init(Cipher.ENCRYPT_MODE,
                    materials.dataKey(),
                    new GCMParameterSpec(algorithmSuite.cipherTagLengthBits(), nonce));

            EncryptedContent result = new EncryptedContent();
            result.nonce = nonce;
            result.ciphertext = cipher.doFinal(content);

            return result;
        } catch (NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | InvalidAlgorithmParameterException
                 | InvalidKeyException
                 | IllegalBlockSizeException
                 | BadPaddingException e) {
            throw new S3EncryptionClientException("Unable to " + cipherName + " content encrypt.", e);
        }
    }

    @Override
    public InputStream decryptContent(ContentMetadata contentMetadata, DecryptionMaterials materials,
                                      InputStream ciphertextStream) {
        // Check the size of the object. If it exceeds a predefined limit in default mode,
        // do not buffer it into memory. Throw an exception and instruct the client to
        // reconfigure using Delayed Authentication mode which supports decryption of
        // large objects over an InputStream.
        if (materials.ciphertextLength() > BUFFERED_MAX_CONTENT_LENGTH_BYTES) {
            throw new S3EncryptionClientException(String.format("The object you are attempting to decrypt exceeds the maximum content " +
                    "length allowed in default mode. Please enable Delayed Authentication mode to decrypt objects larger" +
                    "than %d", BUFFERED_MAX_CONTENT_LENGTH_MiB));
        }

        // Buffer the ciphertextStream into a byte array
        byte[] ciphertext;
        try {
            ciphertext = IoUtils.toByteArray(ciphertextStream);
        } catch (IOException e) {
            throw new S3EncryptionClientException("Unexpected exception while buffering ciphertext input stream!", e);
        }

        AlgorithmSuite algorithmSuite = contentMetadata.algorithmSuite();
        SecretKey contentKey = new SecretKeySpec(materials.plaintextDataKey(), algorithmSuite.dataKeyAlgorithm());
        final int tagLength = algorithmSuite.cipherTagLengthBits();
        byte[] iv = contentMetadata.contentNonce();
        final Cipher cipher;
        byte[] plaintext;
        try {
            cipher = Cipher.getInstance(algorithmSuite.cipherName());
            cipher.init(Cipher.DECRYPT_MODE, contentKey, new GCMParameterSpec(tagLength, iv));
            plaintext = cipher.doFinal(ciphertext);
        } catch (NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | InvalidAlgorithmParameterException
                 | InvalidKeyException
                 | IllegalBlockSizeException
                 | BadPaddingException e) {
            throw new S3EncryptionClientException("Unable to " + algorithmSuite.cipherName() + " content decrypt.", e);
        }

        return new ByteArrayInputStream(plaintext);
    }

    public static class Builder {
        private SecureRandom _secureRandom = new SecureRandom();

        private Builder() {}

        /**
         * Note that this does NOT create a defensive copy of the SecureRandom object. Any modifications to the
         * object will be reflected in this Builder.
         */
        @SuppressFBWarnings(value = "EI_EXPOSE_REP")
        public Builder secureRandom(SecureRandom secureRandom) {
            _secureRandom = secureRandom;
            return this;
        }

        public BufferedAesGcmContentStrategy build() {
            return new BufferedAesGcmContentStrategy(this);
        }
    }
}
