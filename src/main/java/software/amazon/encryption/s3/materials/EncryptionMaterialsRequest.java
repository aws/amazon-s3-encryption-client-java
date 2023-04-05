// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.util.Collections;
import java.util.Map;

import software.amazon.awssdk.services.s3.model.S3Request;

final public class EncryptionMaterialsRequest {

    private final S3Request _s3Request;
    private final Map<String, String> _encryptionContext;
    private final long _plaintextLength;

    private EncryptionMaterialsRequest(Builder builder) {
        this._s3Request = builder._s3Request;
        this._encryptionContext = builder._encryptionContext;
        this._plaintextLength = builder._plaintextLength;
    }

    static public Builder builder() {
        return new Builder();
    }

    public S3Request s3Request() {
        return _s3Request;
    }

    public long plaintextLength() {
        return _plaintextLength;
    }

    /**
     * Note that the underlying implementation uses a Collections.unmodifiableMap which is
     * immutable.
     */
    @SuppressFBWarnings(value = "EI_EXPOSE_REP", justification = "False positive; underlying"
        + " implementation is immutable")
    public Map<String, String> encryptionContext() {
        return _encryptionContext;
    }

    static public class Builder {

        public S3Request _s3Request = null;
        private Map<String, String> _encryptionContext = Collections.emptyMap();
        private long _plaintextLength = -1;

        private Builder() {
        }

        public Builder s3Request(S3Request s3Request) {
            _s3Request = s3Request;
            return this;
        }

        public Builder encryptionContext(Map<String, String> encryptionContext) {
            _encryptionContext = encryptionContext == null
                    ? Collections.emptyMap()
                    : Collections.unmodifiableMap(encryptionContext);
            return this;
        }

        public Builder plaintextLength(final long plaintextLength) {
            _plaintextLength = plaintextLength;
            return this;
        }

        public EncryptionMaterialsRequest build() {
            return new EncryptionMaterialsRequest(this);
        }
    }
}
