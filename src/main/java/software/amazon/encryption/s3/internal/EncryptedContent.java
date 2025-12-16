// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.async.AsyncRequestBody;

public class EncryptedContent {


    private AsyncRequestBody _encryptedRequestBody;
    private long _ciphertextLength = -1;
    protected byte[] _iv;
    protected byte[] _messageId;

    public EncryptedContent(final byte[] iv, final byte[] messageId,final AsyncRequestBody encryptedRequestBody, final long ciphertextLength) {
        _iv = iv;
        _messageId = messageId;
        _encryptedRequestBody = encryptedRequestBody;
        _ciphertextLength = ciphertextLength;
    }

    //= specification/s3-encryption/encryption.md#content-encryption
    //# The generated IV or Message ID MUST be set or returned from the encryption process such that it can be included in the content metadata.
    public byte[] messageId() {
        return _messageId != null ? _messageId.clone() : null;
    }

    //= specification/s3-encryption/encryption.md#content-encryption
    //# The generated IV or Message ID MUST be set or returned from the encryption process such that it can be included in the content metadata.
    public byte[] iv() {
        return _iv != null ? _iv.clone() : null;
    }

    public long getCiphertextLength() {
        return _ciphertextLength;
    }

    public AsyncRequestBody getAsyncCiphertext() {
        return _encryptedRequestBody;
    }

}
