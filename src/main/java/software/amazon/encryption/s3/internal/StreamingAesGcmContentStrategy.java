// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import java.security.SecureRandom;

import javax.crypto.Cipher;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

public class StreamingAesGcmContentStrategy implements AsyncContentEncryptionStrategy, MultipartContentEncryptionStrategy {

    final private SecureRandom _secureRandom;

    private StreamingAesGcmContentStrategy(Builder builder) {
        this._secureRandom = builder._secureRandom;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public MultipartEncryptedContent initMultipartEncryption(EncryptionMaterials materials) {
        //= specification/s3-encryption/encryption.md#content-encryption
        //# The client MUST validate that the length of the plaintext bytes does not exceed the algorithm suite's cipher's maximum content length in bytes.
        if (materials.getPlaintextLength() > materials.algorithmSuite().cipherMaxContentLengthBytes()) {
            throw new S3EncryptionClientException("The contentLength of the object you are attempting to encrypt exceeds" +
                    "the maximum length allowed for GCM encryption.");
        }


        //= specification/s3-encryption/encryption.md#content-encryption
        //# The client MUST generate an IV or Message ID using the length of the IV or Message ID defined in the algorithm suite.
        final byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];
        _secureRandom.nextBytes(iv);

        final Cipher cipher = CipherProvider.createAndInitCipher(materials, iv, null);
        return new MultipartEncryptedContent(iv, null, cipher, materials.getCiphertextLength());
    }

    @Override
    public EncryptedContent encryptContent(EncryptionMaterials materials, AsyncRequestBody content) {
        //= specification/s3-encryption/encryption.md#content-encryption
        //# The client MUST validate that the length of the plaintext bytes does not exceed the algorithm suite's cipher's maximum content length in bytes.
        if (materials.getPlaintextLength() > materials.algorithmSuite().cipherMaxContentLengthBytes()) {
            throw new S3EncryptionClientException("The contentLength of the object you are attempting to encrypt exceeds" +
                    "the maximum length allowed for GCM encryption.");
        }

        //= specification/s3-encryption/encryption.md#content-encryption
        //# The client MUST generate an IV or Message ID using the length of the IV or Message ID defined in the algorithm suite.
        final byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];
        _secureRandom.nextBytes(iv);

        AsyncRequestBody encryptedAsyncRequestBody = new CipherAsyncRequestBody(content, materials.getCiphertextLength(), materials, iv, null);
        return new EncryptedContent(iv, null, encryptedAsyncRequestBody, materials.getCiphertextLength());
    }

    public static class Builder {
        private SecureRandom _secureRandom = new SecureRandom();

        private Builder() {
        }

        /**
         * Note that this does NOT create a defensive copy of the SecureRandom object. Any modifications to the
         * object will be reflected in this Builder.
         */
        @SuppressFBWarnings(value = "EI_EXPOSE_REP")
        public Builder secureRandom(SecureRandom secureRandom) {
            if (secureRandom == null) {
                throw new S3EncryptionClientException("SecureRandom provided to StreamingAesGcmContentStrategy cannot be null");
            }
            _secureRandom = secureRandom;
            return this;
        }

        public StreamingAesGcmContentStrategy build() {
            return new StreamingAesGcmContentStrategy(this);
        }
    }
}
