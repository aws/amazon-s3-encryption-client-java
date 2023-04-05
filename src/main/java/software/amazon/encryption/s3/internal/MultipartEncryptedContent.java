// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.async.AsyncRequestBody;

import javax.crypto.Cipher;

public class MultipartEncryptedContent extends EncryptedContent {
    private final Cipher _cipher;

    public MultipartEncryptedContent(byte[] iv, Cipher cipher, long ciphertextLength) {
        super(iv, null, ciphertextLength);
        _cipher = cipher;
        _iv = iv;
    }

    /**
     * MultipartEncryptedContent cannot store a ciphertext AsyncRequestBody
     * as it one is generated for each part using the cipher in this class.
     * @throws UnsupportedOperationException always
     */
    @Override
    public AsyncRequestBody getAsyncCiphertext() {
        throw new UnsupportedOperationException("MultipartEncryptedContent does not support async ciphertext!");
    }

    /**
     * @return the cipher used for the duration of the multipart upload
     */
    public Cipher getCipher() {
        return _cipher;
    }
}
