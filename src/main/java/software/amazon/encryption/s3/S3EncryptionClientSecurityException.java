// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

/**
 * Exception class for security-related errors in the S3 Encryption Client.
 * This exception is thrown when security violations or cryptographic failures occur,
 * such as authentication tag validation failures, key commitment mismatches, or other
 * security-critical errors that could indicate tampering or corruption of encrypted data.
 */
public class S3EncryptionClientSecurityException extends S3EncryptionClientException {

    /**
     * Constructs a new S3EncryptionClientSecurityException with the specified error message.
     * @param message a description of the security error
     */
    public S3EncryptionClientSecurityException(String message) {
        super(message);
    }

    /**
     * Constructs a new S3EncryptionClientSecurityException with the specified error message and cause.
     * @param message a description of the security error
     * @param cause the underlying cause of this security exception
     */
    public S3EncryptionClientSecurityException(String message, Throwable cause) {
        super(message, cause);
    }
}
