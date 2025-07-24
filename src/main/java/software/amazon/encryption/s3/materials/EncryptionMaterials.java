// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.services.s3.model.S3Request;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.CipherMode;
import software.amazon.encryption.s3.internal.CipherProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.util.Collections;
import java.util.List;
import java.util.Map;

final public class EncryptionMaterials implements CryptographicMaterials {

    // Original request
    private final S3Request _s3Request;

    // Identifies what sort of crypto algorithms we want to use
    private final AlgorithmSuite _algorithmSuite;

    // Additional information passed into encrypted that is required on decryption as well
    // Should NOT contain sensitive information
    private final Map<String, String> _encryptionContext;

    private final List<EncryptedDataKey> _encryptedDataKeys;
    private final byte[] _plaintextDataKey;
    private final Provider _cryptoProvider;
    private final long _plaintextLength;
    private final long _ciphertextLength;

    private EncryptionMaterials(Builder builder) {
        this._s3Request = builder._s3Request;
        this._algorithmSuite = builder._algorithmSuite;
        this._encryptionContext = builder._encryptionContext;
        this._encryptedDataKeys = builder._encryptedDataKeys;
        this._plaintextDataKey = builder._plaintextDataKey;
        this._cryptoProvider = builder._cryptoProvider;
        this._plaintextLength = builder._plaintextLength;
        this._ciphertextLength = _plaintextLength + _algorithmSuite.cipherTagLengthBytes();
    }

    static public Builder builder() {
        return new Builder();
    }

    public S3Request s3Request() {
        return _s3Request;
    }

    public AlgorithmSuite algorithmSuite() {
        return _algorithmSuite;
    }

    /**
     * Note that the underlying implementation uses a Collections.unmodifiableMap which is
     * immutable.
     */
    @Override
    @SuppressFBWarnings(value = "EI_EXPOSE_REP", justification = "False positive; underlying"
        + " implementation is immutable")
    public Map<String, String> encryptionContext() {
        return _encryptionContext;
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

    public byte[] plaintextDataKey() {
        if (_plaintextDataKey == null) {
            return null;
        }
        return _plaintextDataKey.clone();
    }

    public long getPlaintextLength() {
        return _plaintextLength;
    }

    public long getCiphertextLength() {
        return _ciphertextLength;
    }

    public SecretKey dataKey() {
        return new SecretKeySpec(_plaintextDataKey, algorithmSuite().dataKeyAlgorithm());
    }

    public Provider cryptoProvider() {
        return _cryptoProvider;
    }

    @Override
    public CipherMode cipherMode() {
        return CipherMode.ENCRYPT;
    }

    @Override
    public Cipher getCipher(byte[] iv) {
        return CipherProvider.createAndInitCipher(this, iv);
    }

    public Builder toBuilder() {
        return new Builder()
                .s3Request(_s3Request)
                .algorithmSuite(_algorithmSuite)
                .encryptionContext(_encryptionContext)
                .encryptedDataKeys(_encryptedDataKeys)
                .plaintextDataKey(_plaintextDataKey)
                .cryptoProvider(_cryptoProvider)
                .plaintextLength(_plaintextLength);
    }

    static public class Builder {

        private S3Request _s3Request = null;

        private AlgorithmSuite _algorithmSuite = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
        private Map<String, String> _encryptionContext = Collections.emptyMap();
        private List<EncryptedDataKey> _encryptedDataKeys = Collections.emptyList();
        private byte[] _plaintextDataKey = null;
        private long _plaintextLength = -1;
        private Provider _cryptoProvider = null;

        private Builder() {
        }

        public Builder s3Request(S3Request s3Request) {
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

        public Builder encryptedDataKeys(List<EncryptedDataKey> encryptedDataKeys) {
            _encryptedDataKeys = encryptedDataKeys == null
                    ? Collections.emptyList()
                    : Collections.unmodifiableList(encryptedDataKeys);
            return this;
        }

        public Builder plaintextDataKey(byte[] plaintextDataKey) {
            _plaintextDataKey = plaintextDataKey == null ? null : plaintextDataKey.clone();
            return this;
        }
        public Builder cryptoProvider(Provider cryptoProvider) {
            _cryptoProvider = cryptoProvider;
            return this;
        }

        public Builder plaintextLength(long plaintextLength) {
            _plaintextLength = plaintextLength;
            return this;
        }

        public EncryptionMaterials build() {
            return new EncryptionMaterials(this);
        }
    }
}
