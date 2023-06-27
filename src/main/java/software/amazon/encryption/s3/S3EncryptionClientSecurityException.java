// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

public class S3EncryptionClientSecurityException extends S3EncryptionClientException {

    public S3EncryptionClientSecurityException(String message) {
        super(message);
    }

    public S3EncryptionClientSecurityException(String message, Throwable cause) {
        super(message, cause);
    }
}
