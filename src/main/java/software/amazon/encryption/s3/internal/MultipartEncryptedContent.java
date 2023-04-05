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
