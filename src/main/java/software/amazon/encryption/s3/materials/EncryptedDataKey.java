// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

public class EncryptedDataKey {

    // forms the "domain" of the key e.g. "aws-kms"
    private final String _keyProviderId;

    // a unique identifer e.g. an ARN
    private final byte[] _keyProviderInfo;
    // Encrypted data key ciphertext
    private final byte[] _encryptedDataKey;

    private EncryptedDataKey(Builder builder) {
        this._keyProviderId = builder._keyProviderId;
        this._keyProviderInfo = builder._keyProviderInfo;
        this._encryptedDataKey = builder._encryptedDataKey;
    }

    static public Builder builder() {
        return new Builder();
    }

    public String keyProviderId() {
        return _keyProviderId;
    }

    public byte[] keyProviderInfo() {
        if (_keyProviderInfo == null) {
            return null;
        }
        return _keyProviderInfo.clone();
    }

    public byte[] encryptedDatakey() {
        if (_encryptedDataKey == null) {
            return null;
        }

        return _encryptedDataKey.clone();
    }

    static public class Builder {

        private String _keyProviderId = null;
        private byte[] _keyProviderInfo = null;
        private byte[] _encryptedDataKey = null;

        private Builder() {
        }

        public Builder keyProviderId(String keyProviderId) {
            _keyProviderId = keyProviderId;
            return this;
        }

        public Builder keyProviderInfo(byte[] keyProviderInfo) {
            _keyProviderInfo = keyProviderInfo == null ? null : keyProviderInfo.clone();
            return this;
        }

        public Builder encryptedDataKey(byte[] encryptedDataKey) {
            _encryptedDataKey = encryptedDataKey == null ? null : encryptedDataKey.clone();
            return this;
        }

        public EncryptedDataKey build() {
            return new EncryptedDataKey(this);
        }
    }
}
