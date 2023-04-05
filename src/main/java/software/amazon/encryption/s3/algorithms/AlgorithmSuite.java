/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package software.amazon.encryption.s3.algorithms;

public enum AlgorithmSuite {
    ALG_AES_256_GCM_IV12_TAG16_NO_KDF(0x0072,
            false,
            "AES",
            256,
            "AES/GCM/NoPadding",
            128,
            96,
            128,
            AlgorithmConstants.GCM_MAX_CONTENT_LENGTH_BITS),
    ALG_AES_256_CTR_IV16_TAG16_NO_KDF(0x0071,
            true,
            "AES",
            256,
            "AES/CTR/NoPadding",
            128,
            128,
            128,
            AlgorithmConstants.CTR_MAX_CONTENT_LENGTH_BYTES),
    ALG_AES_256_CBC_IV16_NO_KDF(0x0070,
            true,
            "AES",
            256,
            "AES/CBC/PKCS5Padding",
            128,
            128,
            0,
            AlgorithmConstants.CBC_MAX_CONTENT_LENGTH_BYTES);

    private int _id;
    private boolean _isLegacy;
    private String _dataKeyAlgorithm;
    private int _dataKeyLengthBits;
    private String _cipherName;
    private int _cipherBlockSizeBits;
    private int _cipherIvLengthBits;
    private int _cipherTagLengthBits;
    private long _cipherMaxContentLengthBits;

    AlgorithmSuite(int id,
                   boolean isLegacy,
                   String dataKeyAlgorithm,
                   int dataKeyLengthBits,
                   String cipherName,
                   int cipherBlockSizeBits,
                   int cipherIvLengthBits,
                   int cipherTagLengthBits,
                   long cipherMaxContentLengthBits
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
    }

    public int id() {
        return _id;
    }

    public boolean isLegacy() {
        return _isLegacy;
    }

    public String dataKeyAlgorithm() {
        return _dataKeyAlgorithm;
    }

    public int dataKeyLengthBits() {
        return _dataKeyLengthBits;
    }

    public String cipherName() {
        return _cipherName;
    }

    public int cipherTagLengthBits() {
        return _cipherTagLengthBits;
    }

    public int cipherTagLengthBytes() {
        return _cipherTagLengthBits / 8;
    }

    public int iVLengthBytes() {
        return _cipherIvLengthBits / 8;
    }

    public int cipherBlockSizeBytes() {
        return _cipherBlockSizeBits / 8;
    }

    public long cipherMaxContentLengthBits() {
        return _cipherMaxContentLengthBits;
    }

    public long cipherMaxContentLengthBytes() {
        return _cipherMaxContentLengthBits / 8;
    }
}
