// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.services.s3.model.S3Request;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.CryptographicMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

public class MultipartUploadMaterials implements CryptographicMaterials {

    // Original request
    private final S3Request _s3Request;

    // Identifies what sort of crypto algorithms we want to use
    private final AlgorithmSuite _algorithmSuite;

    // Additional information passed into encrypted that is required on decryption as well
    // Should NOT contain sensitive information
    private final Map<String, String> _encryptionContext;

    private final byte[] _plaintextDataKey;
    private final Provider _cryptoProvider;
    private long _plaintextLength;
    private boolean hasFinalPartBeenSeen;
    private final Cipher _cipher;

    private MultipartUploadMaterials(Builder builder) {
        this._s3Request = builder._s3Request;
        this._algorithmSuite = builder._algorithmSuite;
        this._encryptionContext = builder._encryptionContext;
        this._plaintextDataKey = builder._plaintextDataKey;
        this._cryptoProvider = builder._cryptoProvider;
        this._plaintextLength = builder._plaintextLength;
        this._cipher = builder._cipher;
    }

    static public Builder builder() {
        return new Builder();
    }

    public final boolean hasFinalPartBeenSeen() {
        return hasFinalPartBeenSeen;
    }

    public final void setHasFinalPartBeenSeen(boolean hasFinalPartBeenSeen) {
        this.hasFinalPartBeenSeen = hasFinalPartBeenSeen;
    }

    /**
     * Can be used to enforce serial uploads.
     */
    private int partNumber;

    /**
     * True if a multipart upload is currently in progress; false otherwise.
     */
    private volatile boolean partUploadInProgress;

    /**
     * When calling with an IV, sanity check that the given IV matches the
     * one in the cipher. Then just return the cipher.
     */
    @Override
    public Cipher getCipher(byte[] iv) {
        if (!Arrays.equals(iv, _cipher.getIV())) {
            throw new S3EncryptionClientException("IVs in MultipartUploadMaterials do not match!");
        }
        return _cipher;
    }

    public byte[] getIv() {
        return _cipher.getIV();
    }

    /**
     * Can be used to check the next part number must either be the same (if it
     * was a retry) or increment by exactly 1 during a serial part uploads.
     * <p>
     * As a side effect, the {@link #partUploadInProgress} will be set to true
     * upon successful completion of this method. Caller of this method is
     * responsible to call {@link #endPartUpload()} in a finally block once
     * the respective part-upload is completed (either normally or abruptly).
     *
     * @throws S3EncryptionClientException if parallel part upload is detected
     * @see #endPartUpload()
     */
    protected void beginPartUpload(final int nextPartNumber, final long partContentLength) {
        if (nextPartNumber < 1)
            throw new IllegalArgumentException("part number must be at least 1");
        if (partUploadInProgress) {
            throw new S3EncryptionClientException(
                    "Parts are required to be uploaded in series");
        }
        synchronized (this) {
            if (nextPartNumber - partNumber <= 1) {
                partNumber = nextPartNumber;
                partUploadInProgress = true;
                incrementPlaintextSize(partContentLength);
            } else {
                throw new S3EncryptionClientException(
                        "Parts are required to be uploaded in series (partNumber="
                                + partNumber + ", nextPartNumber="
                                + nextPartNumber + ")");
            }
        }
    }

    /**
     * Increments the plaintextSize as parts come in, checking to
     * ensure that the max GCM size limit is not exceeded.
     * @param lengthOfPartToAdd the length of the incoming part
     * @return the new _plaintextLength value
     */
    private synchronized long incrementPlaintextSize(final long lengthOfPartToAdd) {
        if (_plaintextLength + lengthOfPartToAdd > AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherMaxContentLengthBytes()) {
            throw new S3EncryptionClientException("The contentLength of the object you are attempting to encrypt exceeds" +
                    "the maximum length allowed for GCM encryption.");
        }
        _plaintextLength += lengthOfPartToAdd;
        return _plaintextLength;
    }

    /**
     * Used to mark the completion of a part upload before the next. Should be
     * invoked in finally block, and must be preceded previously by a call to
     * {@link #beginPartUpload(int, long)}.
     *
     * @see #beginPartUpload(int, long)
     */
    protected void endPartUpload() {
        partUploadInProgress = false;
    }

    @Override
    public AlgorithmSuite algorithmSuite() {
        return _algorithmSuite;
    }

    @Override
    public S3Request s3Request() {
        return _s3Request;
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

    @Override
    public SecretKey dataKey() {
        return new SecretKeySpec(_plaintextDataKey, algorithmSuite().dataKeyAlgorithm());
    }

    @Override
    public Provider cryptoProvider() {
        return _cryptoProvider;
    }

    @Override
    public CipherMode cipherMode() {
        return CipherMode.MULTIPART_ENCRYPT;
    }

    static public class Builder {
        private S3Request _s3Request = null;
        private AlgorithmSuite _algorithmSuite = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
        private Map<String, String> _encryptionContext = Collections.emptyMap();
        private byte[] _plaintextDataKey = null;
        private long _plaintextLength = 0;
        private Provider _cryptoProvider = null;
        private Cipher _cipher = null;

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

        public Builder plaintextDataKey(byte[] plaintextDataKey) {
            _plaintextDataKey = plaintextDataKey == null ? null : plaintextDataKey.clone();
            return this;
        }

        public Builder cryptoProvider(Provider cryptoProvider) {
            _cryptoProvider = cryptoProvider;
            return this;
        }

        public Builder cipher(Cipher cipher) {
            _cipher = cipher;
            return this;
        }

        public Builder fromEncryptionMaterials(final EncryptionMaterials materials) {
            _s3Request = materials.s3Request();
            _algorithmSuite = materials.algorithmSuite();
            _encryptionContext = materials.encryptionContext();
            _plaintextDataKey = materials.plaintextDataKey();
            _cryptoProvider = materials.cryptoProvider();
            return this;
        }

        public MultipartUploadMaterials build() {
            return new MultipartUploadMaterials(this);
        }
    }
}