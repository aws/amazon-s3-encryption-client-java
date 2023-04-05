// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import software.amazon.encryption.s3.S3EncryptionClientException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

public class PartialRsaKeyPair implements PartialKeyPair {
    private final PrivateKey _privateKey;
    private final PublicKey _publicKey;

    private static final String RSA_KEY_ALGORITHM = "RSA";

    public PartialRsaKeyPair(final KeyPair keyPair) {
        _privateKey = keyPair.getPrivate();
        _publicKey = keyPair.getPublic();

        validateKeyPair();
    }

    public PartialRsaKeyPair(final PrivateKey privateKey, final PublicKey publicKey) {
        _privateKey = privateKey;
        _publicKey = publicKey;

        validateKeyPair();
    }

    private void validateKeyPair() {
        if (_privateKey == null && _publicKey == null) {
            throw new S3EncryptionClientException("The public key and private cannot both be null. You must provide a " +
                    "public key, or a private key, or both.");
        }

        if (_privateKey != null && !_privateKey.getAlgorithm().equals(RSA_KEY_ALGORITHM)) {
            throw new S3EncryptionClientException("%s is not a supported algorithm. Only RSA keys are supported. Please reconfigure your client with an RSA key.");
        }

        if (_publicKey != null && !_publicKey.getAlgorithm().equals(RSA_KEY_ALGORITHM)) {
            throw new S3EncryptionClientException("%s is not a supported algorithm. Only RSA keys are supported. Please reconfigure your client with an RSA key.");
        }
    }

    @Override
    public PublicKey getPublicKey() {
        if (_publicKey == null) {
            throw new S3EncryptionClientException("No public key provided. You must configure a public key to be able to" +
                    " encrypt data.");
        }
        return _publicKey;
    }

    @Override
    public PrivateKey getPrivateKey() {
        if (_privateKey == null) {
            throw new S3EncryptionClientException("No private key provided. You must configure a private key to be able to" +
                    " decrypt data.");
        }
        return _privateKey;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        PartialRsaKeyPair that = (PartialRsaKeyPair) o;
        return Objects.equals(_privateKey, that._privateKey) && Objects.equals(_publicKey, that._publicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(_privateKey, _publicKey);
    }

    public static class Builder {
        private PublicKey _publicKey;
        private PrivateKey _privateKey;

        private Builder() {}

        public Builder publicKey(final PublicKey publicKey) {
            _publicKey = publicKey;
            return this;
        }

        public Builder privateKey(final PrivateKey privateKey) {
            _privateKey = privateKey;
            return this;
        }

        public PartialRsaKeyPair build() {
            return new PartialRsaKeyPair(_privateKey, _publicKey);
        }
    }
}
