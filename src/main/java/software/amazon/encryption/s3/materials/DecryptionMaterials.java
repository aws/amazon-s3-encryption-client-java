// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.CipherMode;
import software.amazon.encryption.s3.internal.CipherProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.util.Collections;
import java.util.Map;

/**
 * Contains the cryptographic materials needed for a decryption operation.
 *
 * @see CryptographicMaterialsManager#decryptMaterials(DecryptMaterialsRequest)
 */
final public class DecryptionMaterials implements CryptographicMaterials {

    // Original request
    private final GetObjectRequest _s3Request;

    // Identifies what sort of crypto algorithms we want to use
    private final AlgorithmSuite _algorithmSuite;

    // Additional information passed into encrypted that is required on decryption as well
    // Should NOT contain sensitive information
    private final Map<String, String> _encryptionContext;

    // Materials description used for RSA and AES keyrings
    private final MaterialsDescription _materialsDescription;

    private final byte[] _plaintextDataKey;

    final private long _ciphertextLength;
    final private Provider _cryptoProvider;
    final private String _contentRange;
    final private byte[] _keyCommitment;
    private byte[] _messageId;
    private byte[] _iv;

    private DecryptionMaterials(Builder builder) {
        this._s3Request = builder._s3Request;
        this._algorithmSuite = builder._algorithmSuite;
        this._encryptionContext = builder._encryptionContext;
        this._materialsDescription = builder._materialsDescription;
        this._plaintextDataKey = builder._plaintextDataKey;
        this._ciphertextLength = builder._ciphertextLength;
        this._cryptoProvider = builder._cryptoProvider;
        this._contentRange = builder._contentRange;
        this._keyCommitment = builder._keyCommitment;
        this._messageId = builder._messageId;
        this._iv = builder._iv;
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

    public byte[] plaintextDataKey() {
        if (_plaintextDataKey == null) {
            return null;
        }
        return _plaintextDataKey.clone();
    }

    public SecretKey dataKey() {
        return new SecretKeySpec(_plaintextDataKey, algorithmSuite().dataKeyAlgorithm());
    }

    public Provider cryptoProvider() {
        return _cryptoProvider;
    }

    public long ciphertextLength() {
        return _ciphertextLength;
    }

    @Override
    public CipherMode cipherMode() {
        return CipherMode.DECRYPT;
    }

    @Override
    public Cipher getCipher(byte[] iv) {
        return CipherProvider.createAndInitCipher(this, iv, this._messageId);
    }

    public String getContentRange() {
        return _contentRange;
    }

    public byte[] getKeyCommitment() {
        return _keyCommitment != null ? _keyCommitment.clone() : null;
    }

    @Override
    public byte[] messageId() {
        return _messageId;
    }

    @Override
    public byte[] iv() {
        return _iv;
    }

    public void setIvAndMessageId(byte[] iv, byte[] messageId) {
        this._iv = iv;
        this._messageId = messageId;
    }

    public Builder toBuilder() {
        return new Builder()
                .s3Request(_s3Request)
                .algorithmSuite(_algorithmSuite)
                .encryptionContext(_encryptionContext)
                .materialsDescription(_materialsDescription)
                .plaintextDataKey(_plaintextDataKey)
                .ciphertextLength(_ciphertextLength)
                .cryptoProvider(_cryptoProvider)
                .contentRange(_contentRange)
                .keyCommitment(_keyCommitment);
    }

    static public class Builder {

        public GetObjectRequest _s3Request = null;
        public byte[] _messageId = null;
        public byte[] _iv = null;
        private Provider _cryptoProvider = null;
        private AlgorithmSuite _algorithmSuite = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
        private Map<String, String> _encryptionContext = Collections.emptyMap();
        private MaterialsDescription _materialsDescription = MaterialsDescription.builder().build();
        private byte[] _plaintextDataKey = null;
        private long _ciphertextLength = -1;
        private String _contentRange = null;
        private byte[] _keyCommitment = null;

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

        public Builder plaintextDataKey(byte[] plaintextDataKey) {
            _plaintextDataKey = plaintextDataKey == null ? null : plaintextDataKey.clone();
            return this;
        }

        public Builder ciphertextLength(long ciphertextLength) {
            _ciphertextLength = ciphertextLength;
            return this;
        }

        public Builder cryptoProvider(Provider cryptoProvider) {
            _cryptoProvider = cryptoProvider;
            return this;
        }

        public Builder contentRange(String contentRange) {
            _contentRange = contentRange;
            return this;
        }

        public Builder keyCommitment(byte[] keyCommitment) {
            _keyCommitment = keyCommitment;
            return this;
        }

        public Builder iv(byte[] iv) {
            _iv = iv;
            return this;
        }

        public Builder messageId(byte[] messageId) {
            _messageId = messageId;
            return this;
        }

        public DecryptionMaterials build() {
            return new DecryptionMaterials(this);
        }
    }
}
