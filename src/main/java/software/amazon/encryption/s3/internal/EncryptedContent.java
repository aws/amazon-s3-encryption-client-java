// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.async.AsyncRequestBody;

public class EncryptedContent {

    private AsyncRequestBody _encryptedRequestBody;
    private long _ciphertextLength = -1;
    protected byte[] _iv;

    public EncryptedContent(final byte[] iv, final AsyncRequestBody encryptedRequestBody, final long ciphertextLength) {
        _iv = iv;
        _encryptedRequestBody = encryptedRequestBody;
        _ciphertextLength = ciphertextLength;
    }

    public byte[] getIv() {
        return _iv;
    }

    public long getCiphertextLength() {
        return _ciphertextLength;
    }

    public AsyncRequestBody getAsyncCiphertext() {
        return _encryptedRequestBody;
    }

}
