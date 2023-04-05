// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.DecryptionMaterials;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * This class will decrypt AES-GCM encrypted data by buffering the ciphertext
 * stream into memory. This prevents release of unauthenticated plaintext.
 */
public class BufferedAesGcmContentStrategy implements ContentDecryptionStrategy {

    // 64MiB ought to be enough for most usecases
    private static final long BUFFERED_MAX_CONTENT_LENGTH_MiB = 64;
    private static final long BUFFERED_MAX_CONTENT_LENGTH_BYTES = 1024 * 1024 * BUFFERED_MAX_CONTENT_LENGTH_MiB;

    private BufferedAesGcmContentStrategy(Builder builder) {
    }

    public static Builder builder() {
        return new Builder();
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
        byte[] iv = contentMetadata.contentIv();
        final Cipher cipher;
        byte[] plaintext;
        try {
            cipher = CryptoFactory.createCipher(algorithmSuite.cipherName(), materials.cryptoProvider());
            cipher.init(Cipher.DECRYPT_MODE, contentKey, new GCMParameterSpec(tagLength, iv));
            plaintext = cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new S3EncryptionClientException("Unable to " + algorithmSuite.cipherName() + " content decrypt.", e);
        }

        return new ByteArrayInputStream(plaintext);
    }

    public static class Builder {

        private Builder() {
        }

        public BufferedAesGcmContentStrategy build() {
            return new BufferedAesGcmContentStrategy(this);
        }
    }
}
