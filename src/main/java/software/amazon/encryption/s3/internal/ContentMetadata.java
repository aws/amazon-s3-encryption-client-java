// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.MaterialsDescription;

import java.util.Collections;
import java.util.Map;

public class ContentMetadata {

    private final AlgorithmSuite _algorithmSuite;

    private final EncryptedDataKey _encryptedDataKey;
    private final String _encryptedDataKeyAlgorithm;

    /**
     * This field stores the encryption context.
     */
    private final Map<String, String> _encryptionContext;

    /**
     * This field stores the materials description used for RSA and AES keyrings.
     */
    private final MaterialsDescription _materialsDescription;

    private final byte[] _contentIv;
    private final String _contentCipher;
    private final String _contentCipherTagLength;
    private final String _contentRange;

    private ContentMetadata(Builder builder) {
        _algorithmSuite = builder._algorithmSuite;

        _encryptedDataKey = builder._encryptedDataKey;
        _encryptedDataKeyAlgorithm = builder._encryptedDataKeyAlgorithm;
        _encryptionContext = builder._encryptionContext;
        _materialsDescription = builder._materialsDescription;

        _contentIv = builder._contentIv;
        _contentCipher = builder._contentCipher;
        _contentCipherTagLength = builder._contentCipherTagLength;
        _contentRange = builder._contentRange;
    }

    public static Builder builder() {
        return new Builder();
    }

    public AlgorithmSuite algorithmSuite() {
        return _algorithmSuite;
    }

    public EncryptedDataKey encryptedDataKey() {
        return _encryptedDataKey;
    }

    public String encryptedDataKeyAlgorithm() {
        return _encryptedDataKeyAlgorithm;
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

    /**
     * Returns the materials description used for RSA and AES keyrings.
     * @return the materials description
     */
    public MaterialsDescription materialsDescription() {
        return _materialsDescription;
    }

    public byte[] contentIv() {
        if (_contentIv == null) {
            return null;
        }
        return _contentIv.clone();
    }

    public String contentCipher() {
        return _contentCipher;
    }

    public String contentCipherTagLength() {
        return _contentCipherTagLength;
    }

    public String contentRange() {
        return _contentRange;
    }

    public static class Builder {
        private AlgorithmSuite _algorithmSuite;

        private EncryptedDataKey _encryptedDataKey;
        private String _encryptedDataKeyAlgorithm;
        private Map<String, String> _encryptionContext;
        private MaterialsDescription _materialsDescription = MaterialsDescription.builder().build();

        private byte[] _contentIv;
        private String _contentCipher;
        private String _contentCipherTagLength;
        public String _contentRange;

        private Builder() {

        }

        public Builder algorithmSuite(AlgorithmSuite algorithmSuite) {
            _algorithmSuite = algorithmSuite;
            return this;
        }

        public Builder encryptedDataKey(EncryptedDataKey encryptedDataKey) {
            _encryptedDataKey = encryptedDataKey;
            return this;
        }

        public Builder encryptedDataKeyAlgorithm(String encryptedDataKeyAlgorithm) {
            _encryptedDataKeyAlgorithm = encryptedDataKeyAlgorithm;
            return this;
        }

        public Builder encryptionContext(Map<String, String> encryptionContext) {
            _encryptionContext = Collections.unmodifiableMap(encryptionContext);
            return this;
        }

        public Builder materialsDescription(MaterialsDescription materialsDescription) {
            _materialsDescription = materialsDescription == null
                    ? MaterialsDescription.builder().build()
                    : materialsDescription;
            return this;
        }

        public Builder contentIv(byte[] contentIv) {
            _contentIv = contentIv.clone();
            return this;
        }

        public Builder contentRange(String contentRange) {
            _contentRange = contentRange;
            return this;
        }

        public ContentMetadata build() {
            return new ContentMetadata(this);
        }
    }

}
