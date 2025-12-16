// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class DecryptMaterialsRequest {

    private final GetObjectRequest _s3Request;
    private final AlgorithmSuite _algorithmSuite;
    private final List<EncryptedDataKey> _encryptedDataKeys;
    private final Map<String, String> _encryptionContext;
    private final MaterialsDescription _materialsDescription;
    private final long _ciphertextLength;
    private final String _contentRange;

    private DecryptMaterialsRequest(Builder builder) {
        this._s3Request = builder._s3Request;
        this._algorithmSuite = builder._algorithmSuite;
        this._encryptedDataKeys = builder._encryptedDataKeys;
        this._encryptionContext = builder._encryptionContext;
        this._materialsDescription = builder._materialsDescription;
        this._ciphertextLength = builder._ciphertextLength;
        this._contentRange = builder._contentRange;
    }

    static public Builder builder() {
        return new Builder();
    }

    public GetObjectRequest s3Request() {
        return _s3Request;
    }

    public AlgorithmSuite algorithmSuite() {
        return _algorithmSuite;
    }

    /**
     * Note that the underlying implementation uses a Collections.unmodifiableList which is
     * immutable.
     */
    @SuppressFBWarnings(value = "EI_EXPOSE_REP", justification = "False positive; underlying"
            + " implementation is immutable")
    public List<EncryptedDataKey> encryptedDataKeys() {
        return _encryptedDataKeys;
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
     *
     * @return the materials description
     */
    public MaterialsDescription materialsDescription() {
        return _materialsDescription;
    }

    public long ciphertextLength() {
        return _ciphertextLength;
    }

    public String contentRange() {
        return _contentRange;
    }

    static public class Builder {

        public GetObjectRequest _s3Request = null;
        private AlgorithmSuite _algorithmSuite = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
        private Map<String, String> _encryptionContext = Collections.emptyMap();
        private MaterialsDescription _materialsDescription = MaterialsDescription.builder().build();
        private List<EncryptedDataKey> _encryptedDataKeys = Collections.emptyList();
        private long _ciphertextLength = -1;
        private String _contentRange = null;

        private Builder() {
        }

        public Builder s3Request(GetObjectRequest s3Request) {
            _s3Request = s3Request;
            return this;
        }

        public Builder algorithmSuite(AlgorithmSuite algorithmSuite) {
            _algorithmSuite = algorithmSuite;
            return this;
        }

        public Builder encryptionContext(Map<String, String> encryptionContext) {
            _encryptionContext = encryptionContext == null
                    ? Collections.emptyMap()
                    : Collections.unmodifiableMap(encryptionContext);
            return this;
        }

        public Builder materialsDescription(MaterialsDescription materialsDescription) {
            _materialsDescription = materialsDescription == null
                    ? MaterialsDescription.builder().build()
                    : materialsDescription;
            return this;
        }

        public Builder encryptedDataKeys(List<EncryptedDataKey> encryptedDataKeys) {
            _encryptedDataKeys = encryptedDataKeys == null
                    ? Collections.emptyList()
                    : Collections.unmodifiableList(encryptedDataKeys);
            return this;
        }

        public Builder ciphertextLength(long ciphertextLength) {
            _ciphertextLength = ciphertextLength;
            return this;
        }

        public Builder contentRange(String range) {
            _contentRange = range;
            return this;
        }

        public DecryptMaterialsRequest build() {
            return new DecryptMaterialsRequest(this);
        }
    }
}
