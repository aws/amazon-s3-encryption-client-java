package software.amazon.encryption.s3.algorithms;


public enum AlgorithmSuite {
    ALG_AES_256_GCM_NO_KDF(0x0078,
            "AES",
            256,
            "AES/GCM/NoPadding",
            128,
            96,
            128,
            Constants.GCM_MAX_CONTENT_LENGTH_BITS);

    private int _id;
    private String _dataKeyAlgorithm;
    private int _dataKeyLengthBits;
    private String _cipherName;
    private int _cipherBlockSizeBits;
    private int _cipherNonceLengthBits;
    private int _cipherTagLengthBits;
    private long _cipherMaxContentLengthBits;

    AlgorithmSuite(int id,
            String dataKeyAlgorithm,
            int dataKeyLengthBits,
            String cipherName,
            int cipherBlockSizeBits,
            int cipherNonceLengthBits,
            int cipherTagLengthBits,
            long cipherMaxContentLengthBits
    ) {
        this._id = id;
        this._dataKeyAlgorithm = dataKeyAlgorithm;
        this._dataKeyLengthBits = dataKeyLengthBits;
        this._cipherName = cipherName;
        this._cipherBlockSizeBits = cipherBlockSizeBits;
        this._cipherNonceLengthBits = cipherNonceLengthBits;
        this._cipherTagLengthBits = cipherTagLengthBits;
        this._cipherMaxContentLengthBits = cipherMaxContentLengthBits;
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

    public int nonceLengthBytes() {
        return _cipherNonceLengthBits / 8;
    }
}
