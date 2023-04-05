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

final public class DecryptionMaterials implements CryptographicMaterials {

    // Original request
    private final GetObjectRequest _s3Request;

    // Identifies what sort of crypto algorithms we want to use
    private final AlgorithmSuite _algorithmSuite;

    // Additional information passed into encrypted that is required on decryption as well
    // Should NOT contain sensitive information
    private final Map<String, String> _encryptionContext;

    private final byte[] _plaintextDataKey;

    private long _ciphertextLength;
    private Provider _cryptoProvider;

    private DecryptionMaterials(Builder builder) {
        this._s3Request = builder._s3Request;
        this._algorithmSuite = builder._algorithmSuite;
        this._encryptionContext = builder._encryptionContext;
        this._plaintextDataKey = builder._plaintextDataKey;
        this._ciphertextLength = builder._ciphertextLength;
        this._cryptoProvider = builder._cryptoProvider;
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
        return CipherProvider.createAndInitCipher(this, iv);
    }

    public Builder toBuilder() {
        return new Builder()
                .s3Request(_s3Request)
                .algorithmSuite(_algorithmSuite)
                .encryptionContext(_encryptionContext)
                .plaintextDataKey(_plaintextDataKey)
                .ciphertextLength(_ciphertextLength)
                .cryptoProvider(_cryptoProvider);
    }

    static public class Builder {

        public GetObjectRequest _s3Request = null;
        private Provider _cryptoProvider = null;
        private AlgorithmSuite _algorithmSuite = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
        private Map<String, String> _encryptionContext = Collections.emptyMap();
        private byte[] _plaintextDataKey = null;
        private long _ciphertextLength = -1;

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

        public DecryptionMaterials build() {
            return new DecryptionMaterials(this);
        }
    }
}
