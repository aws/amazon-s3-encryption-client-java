// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.algorithms;

/**
 * Defines the cryptographic algorithms available for encrypting and decrypting S3 objects.
 * Each algorithm suite specifies the cipher, key derivation function, block size, IV length, tag length, and whether it supports key commitment.
 * <p>
 * Key commitment protects Instruction Files by cryptographically binding the data key to the encrypted object,
 * preventing the data key stored in an Instruction File from being tampered with.
 * <p>
 * For more information, refer to the <a href=https://docs.aws.amazon.com/amazon-s3-encryption-client/latest/developerguide/concepts.html)>Developer Guide.</a>
 */
public enum AlgorithmSuite {
    /**
     * AES-256-GCM with HKDF-SHA512 key derivation and key commitment support.
     * This is a recommended algorithm suite providing maximum security with key commitment guarantees.
     * Supports both encryption and decryption operations.
     * This is the default algorithm for v4 clients.
     * <p>
     * V3 clients (only v3.6.0 or later) can only use this suite to read objects with key commitment;
     * to use this suite to write objects with key commitment, upgrade to a v4 client.
     */
    ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY(0x0073,
            false,
            "AES",
            256, // this is the input into the KDF
            "AES/GCM/NoPadding",
            128,
            96,
            128,
            AlgorithmConstants.GCM_MAX_CONTENT_LENGTH_BITS,
            true,
            224,
            224,
            "HmacSHA512"),
    /**
     * AES-256-CTR with HKDF-SHA512 key derivation and key commitment support.
     * This algorithm suite is used only for decrypting ranged get operations with key commitment.
     * Does not support encryption operations.
     */
    ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY(0x0074,
            true,
            "AES",
            256, // this is the input into the KDF
            "AES/CTR/NoPadding",
            128,
            128,
            128,
            AlgorithmConstants.CTR_MAX_CONTENT_LENGTH_BYTES,
            true,
            224,
            224,
            "HmacSHA512"),
    /**
     * AES-256-GCM without key derivation function or key commitment.
     * This algorithm suite does not support key commitment and is maintained for backward compatibility.
     * This is the default algorithm suite for v3 clients.
     * <p>
     * Content encrypted with this algorithm suite can be read by any v2, v3, or v4 client.
     * Supports both encryption and decryption operations.
     */
    ALG_AES_256_GCM_IV12_TAG16_NO_KDF(0x0072,
            false,
            "AES",
            256,
            "AES/GCM/NoPadding",
            128,
            96,
            128,
            AlgorithmConstants.GCM_MAX_CONTENT_LENGTH_BITS,
            false,
            0,
            0,
            ""),
    /**
     * AES-256-CTR without key derivation function or key commitment.
     * This is a legacy algorithm suite used only for decrypting ranged get operations.
     * Does not support encryption operations.
     */
    ALG_AES_256_CTR_IV16_TAG16_NO_KDF(0x0071,
            true,
            "AES",
            256,
            "AES/CTR/NoPadding",
            128,
            128,
            128,
            AlgorithmConstants.CTR_MAX_CONTENT_LENGTH_BYTES,
            false,
            0,
            0,
            ""),
    /**
     * AES-256-CBC without key derivation function or key commitment.
     * This is a legacy algorithm suite used only for decrypting legacy objects.
     * Does not support encryption operations or authentication.
     */
    ALG_AES_256_CBC_IV16_NO_KDF(0x0070,
            true,
            "AES",
            256,
            "AES/CBC/PKCS5Padding",
            128,
            128,
            0,
            AlgorithmConstants.CBC_MAX_CONTENT_LENGTH_BYTES,
            false,
            0,
            0,
            "");

    private final int _id;
    private final boolean _isLegacy;
    private final String _dataKeyAlgorithm;
    private final int _dataKeyLengthBits;
    private final String _cipherName;
    private final int _cipherBlockSizeBits;
    private final int _cipherIvLengthBits;
    private final int _cipherTagLengthBits;
    private final long _cipherMaxContentLengthBits;
    private final boolean _isCommitting;
    private final int _commitmentLengthBits;
    private final int _commitmentNonceLengthBits;
    private final String _kdfHashAlgorithm;

    AlgorithmSuite(int id,
                   boolean isLegacy,
                   String dataKeyAlgorithm,
                   int dataKeyLengthBits,
                   String cipherName,
                   int cipherBlockSizeBits,
                   int cipherIvLengthBits,
                   int cipherTagLengthBits,
                   long cipherMaxContentLengthBits,
                   boolean isCommitting,
                   int commitmentLength,
                   int commitmentNonceLengthBits,
                   String kdfHashAlgorithm
    ) {
        this._id = id;
        this._isLegacy = isLegacy;
        this._dataKeyAlgorithm = dataKeyAlgorithm;
        this._dataKeyLengthBits = dataKeyLengthBits;
        this._cipherName = cipherName;
        this._cipherBlockSizeBits = cipherBlockSizeBits;
        this._cipherIvLengthBits = cipherIvLengthBits;
        this._cipherTagLengthBits = cipherTagLengthBits;
        this._cipherMaxContentLengthBits = cipherMaxContentLengthBits;
        this._isCommitting = isCommitting;
        this._commitmentLengthBits = commitmentLength;
        this._commitmentNonceLengthBits = commitmentNonceLengthBits;
        this._kdfHashAlgorithm = kdfHashAlgorithm;
    }

    /**
     * Returns the numeric identifier for this algorithm suite used in the encrypted message format.
     * @return the algorithm suite ID as an integer
     */
    public int id() {
        return _id;
    }

    /**
     * Returns the algorithm suite ID as a string representation.
     * @return the algorithm suite ID as a string
     */
    public String idAsString() {
        return String.valueOf(_id);
    }

    /**
     * Returns the algorithm suite ID as a 2-byte array in big-endian format.
     * @return the algorithm suite ID as a byte array
     */
    public byte[] idAsBytes() {
        return new byte[]{(byte) (_id >> 8), (byte) (_id)};
    }

    /**
     * Indicates whether this algorithm suite is considered legacy and may have security limitations.
     * @return {@code true} if this is a legacy algorithm suite
     */
    public boolean isLegacy() {
        return _isLegacy;
    }

    /**
     * Returns the algorithm used for the data key (e.g., "AES").
     * @return the data key algorithm name
     */
    public String dataKeyAlgorithm() {
        return _dataKeyAlgorithm;
    }

    /**
     * Returns the length of the data key in bits.
     * @return the data key length (in bits)
     */
    public int dataKeyLengthBits() {
        return _dataKeyLengthBits;
    }

    /**
     * Returns the length of the data key in bytes.
     * @return the data key length (in bytes)
     */
    public int dataKeyLengthBytes() {
        return _dataKeyLengthBits / 8;
    }

    /**
     * Returns the cipher transformation string used for encryption and decryption (e.g., "AES/GCM/NoPadding").
     * @return the cipher name with mode and padding
     */
    public String cipherName() {
        return _cipherName;
    }

    /**
     * Returns the length of the authentication tag in bits for authenticated encryption modes.
     * @return the tag length (in bits), or 0 if not applicable
     */
    public int cipherTagLengthBits() {
        return _cipherTagLengthBits;
    }

    /**
     * Returns the length of the authentication tag in bytes for authenticated encryption modes.
     * @return the tag length (in bytes), or 0 if not applicable
     */
    public int cipherTagLengthBytes() {
        return _cipherTagLengthBits / 8;
    }

    /**
     * Returns the length of the initialization vector (IV) in bytes.
     * @return the IV length (in bytes)
     */
    public int iVLengthBytes() {
        return _cipherIvLengthBits / 8;
    }

    /**
     * Returns the block size of the cipher in bytes.
     * @return the cipher block size (in bytes)
     */
    public int cipherBlockSizeBytes() {
        return _cipherBlockSizeBits / 8;
    }

    /**
     * Returns the maximum content length in bits that can be encrypted under a single data key.
     * @return the maximum content length (in bits)
     */
    public long cipherMaxContentLengthBits() {
        return _cipherMaxContentLengthBits;
    }

    /**
     * Returns the maximum content length in bytes that can be encrypted under a single data key.
     * @return the maximum content length (in bytes)
     */
    public long cipherMaxContentLengthBytes() {
        return _cipherMaxContentLengthBits / 8;
    }

    /**
     * Indicates whether this algorithm suite supports key commitment.
     * @return {@code true} if key commitment is supported
     */
    public boolean isCommitting() {
        return _isCommitting;
    }

    /**
     * Returns the length of the key commitment value in bits.
     * @return the commitment length (in bits), or 0 if not applicable
     */
    public int commitmentLengthBits() {
        return _commitmentLengthBits;
    }

    /**
     * Returns the length of the key commitment value in bytes.
     * @return the commitment length (in bytes), or 0 if not applicable
     */
    public int commitmentLengthBytes() {
        return _commitmentLengthBits / 8;
    }

    /**
     * Returns the hash algorithm used in the key derivation function (e.g., "HmacSHA512").
     * @return the KDF hash algorithm name, or empty string if no KDF is used
     */
    public String kdfHashAlgorithm() {
        return _kdfHashAlgorithm;
    }

    /**
     * Returns the length of the nonce used for key commitment in bits.
     * @return the commitment nonce length (in bits), or 0 if not applicable
     */
    public int commitmentNonceLengthBits() {
        return _commitmentNonceLengthBits;
    }

    /**
     * Returns the length of the nonce used for key commitment in bytes.
     * @return the commitment nonce length (in bytes), or 0 if not applicable
     */
    public int commitmentNonceLengthBytes() {
        return _commitmentNonceLengthBits / 8;
    }
}
