// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.S3Request;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.CryptographicMaterials;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.MaterialsDescription;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.Provider;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Contains the cryptographic materials needed for multipart upload operations.
 *
 * @see MultipartUploadObjectPipeline#createMultipartUpload(CreateMultipartUploadRequest) 
 */
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
    private byte[] _keyCommitment;
    private byte[] _messageId;
    private byte[] _iv;

    private MultipartUploadMaterials(Builder builder) {
        this._s3Request = builder._s3Request;
        this._algorithmSuite = builder._algorithmSuite;
        this._encryptionContext = builder._encryptionContext;
        this._plaintextDataKey = builder._plaintextDataKey;
        this._cryptoProvider = builder._cryptoProvider;
        this._plaintextLength = builder._plaintextLength;
        this._cipher = builder._cipher;
        this._keyCommitment = builder._keyCommitment;
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
        if (!MessageDigest.isEqual(iv, _cipher.getIV())) {
            throw new S3EncryptionClientException("IVs in MultipartUploadMaterials do not match!");
        }
        return _cipher;
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
     *
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

    @Override
    public byte[] getKeyCommitment() {
        return _keyCommitment != null ? _keyCommitment.clone() : null;
    }

    @Override
    public byte[] messageId() {
        return _messageId != null ? _messageId.clone() : null;
    }

    @Override
    public byte[] iv() {
        return _iv != null ? _iv.clone() : null;
    }

    public void setKeyCommitment(byte[] keyCommitment) {
        _keyCommitment = keyCommitment;
    }

    public void setIvAndMessageId(byte[] iv, byte[] messageId) {
        this._iv = iv;
        this._messageId = messageId;
    }

    static public class Builder {
        private S3Request _s3Request = null;
        private AlgorithmSuite _algorithmSuite = AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
        private Map<String, String> _encryptionContext = Collections.emptyMap();
        private byte[] _plaintextDataKey = null;
        private final long _plaintextLength = 0;
        private Provider _cryptoProvider = null;
        private Cipher _cipher = null;
        private byte[] _keyCommitment = null;
        private MaterialsDescription _materialsDescription = MaterialsDescription.builder().build();
        private List<EncryptedDataKey> _encryptedDataKeys;
        private byte[] _iv;
        private byte[] _messageId;

        private Builder() {
        }

        public Builder cipher(Cipher cipher) {
            _cipher = cipher;
            return this;
        }

        public Builder fromEncryptionMaterials(final EncryptionMaterials materials) {
            _s3Request = materials.s3Request();
            _algorithmSuite = materials.algorithmSuite();
            _encryptionContext = materials.encryptionContext();
            _encryptedDataKeys = materials.encryptedDataKeys();
            _plaintextDataKey = materials.plaintextDataKey();
            _cryptoProvider = materials.cryptoProvider();
            _materialsDescription = materials.materialsDescription();
            _iv = materials.iv();
            _messageId = materials.messageId();
            return this;
        }

        public MultipartUploadMaterials build() {
            return new MultipartUploadMaterials(this);
        }
    }
}