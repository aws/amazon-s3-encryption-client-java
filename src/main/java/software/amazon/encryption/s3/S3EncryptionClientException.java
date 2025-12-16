// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import software.amazon.awssdk.core.exception.SdkClientException;

/**
 * Base exception class for all S3 Encryption Client specific exceptions.
 * This exception is thrown when errors occur during encryption or decryption operations,
 * configuration validation, or other client-specific scenarios.
 */
public class S3EncryptionClientException extends SdkClientException {

    private S3EncryptionClientException(Builder b) {
        super(b);
    }

    /**
     * Constructs a new S3EncryptionClientException with the specified error message.
     * @param message a description of the error
     */
    public S3EncryptionClientException(String message) {
        super(S3EncryptionClientException.builder()
                .message(message));
    }

    /**
     * Constructs a new S3EncryptionClientException with the specified error message and cause.
     * @param message a description of the error
     * @param cause the underlying cause of this exception
     */
    public S3EncryptionClientException(String message, Throwable cause) {
        super(S3EncryptionClientException.builder()
                .message(message)
                .cause(cause));
    }

    @Override
    public Builder toBuilder() {
        return new BuilderImpl(this);
    }

    /**
     * Creates a new builder for constructing S3EncryptionClientException instances.
     * @return a new Builder instance
     */
    public static Builder builder() {
        return new BuilderImpl();
    }

    /**
     * Builder interface for constructing S3EncryptionClientException instances.
     */
    public interface Builder extends SdkClientException.Builder {
        @Override
        Builder message(String message);

        @Override
        Builder cause(Throwable cause);

        @Override
        S3EncryptionClientException build();
    }

    protected static final class BuilderImpl extends SdkClientException.BuilderImpl implements Builder {

        protected BuilderImpl() {
        }

        protected BuilderImpl(S3EncryptionClientException ex) {
            super(ex);
        }

        @Override
        public Builder message(String message) {
            this.message = message;
            return this;
        }

        @Override
        public Builder cause(Throwable cause) {
            this.cause = cause;
            return this;
        }

        @Override
        public S3EncryptionClientException build() {
            return new S3EncryptionClientException(this);
        }
    }
}
