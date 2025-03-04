// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import software.amazon.awssdk.core.exception.SdkClientException;

public class S3EncryptionClientException extends SdkClientException {

    private S3EncryptionClientException(Builder b) {
        super(b);
    }

    public S3EncryptionClientException(String message) {
        super(SdkClientException.builder()
                .message(message));
    }

    public S3EncryptionClientException(String message, Throwable cause) {
        super(SdkClientException.builder()
                .message(message)
                .cause(cause));
    }

    @Override
    public Builder toBuilder() {
        return new BuilderImpl(this);
    }

    public static Builder builder() {
        return new BuilderImpl();
    }

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
