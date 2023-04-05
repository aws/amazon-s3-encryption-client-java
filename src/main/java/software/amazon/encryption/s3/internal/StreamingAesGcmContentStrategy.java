/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

import javax.crypto.Cipher;
import java.security.SecureRandom;

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
        if (materials.getPlaintextLength() > AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherMaxContentLengthBytes()) {
            throw new S3EncryptionClientException("The contentLength of the object you are attempting to encrypt exceeds" +
                    "the maximum length allowed for GCM encryption.");
        }

        final byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];
        _secureRandom.nextBytes(iv);

        final Cipher cipher = CipherProvider.createAndInitCipher(materials, iv);
        return new MultipartEncryptedContent(iv, cipher, materials.getCiphertextLength());
    }

    @Override
    public EncryptedContent encryptContent(EncryptionMaterials materials, AsyncRequestBody content) {
        if (materials.getPlaintextLength() > AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherMaxContentLengthBytes()) {
            throw new S3EncryptionClientException("The contentLength of the object you are attempting to encrypt exceeds" +
                    "the maximum length allowed for GCM encryption.");
        }

        final byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];
        _secureRandom.nextBytes(iv);

        AsyncRequestBody encryptedAsyncRequestBody = new CipherAsyncRequestBody(content, materials.getCiphertextLength(), materials, iv);
        return new EncryptedContent(iv, encryptedAsyncRequestBody, materials.getCiphertextLength());
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
