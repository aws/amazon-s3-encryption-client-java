package software.amazon.encryption.s3.materials;

public class EncryptedDataKey {

    // forms the "domain" of the key e.g. "aws-kms"
    private final String _keyProviderId;

    // a unique identifer e.g. an ARN
    private final byte[] _keyProviderInfo;
    private final byte[] _ciphertext;

    private EncryptedDataKey(Builder builder) {
        this._keyProviderId = builder._keyProviderId;
        this._keyProviderInfo = builder._keyProviderInfo;
        this._ciphertext = builder._ciphertext;
    }

    static public Builder builder() {
        return new Builder();
    }

    public String keyProviderId() {
        return _keyProviderId;
    }

    public byte[] keyProviderInfo() {
        return _keyProviderInfo;
    }

    public byte[] ciphertext() {
        return _ciphertext;
    }

    static public class Builder {

        private String _keyProviderId = null;
        private byte[] _keyProviderInfo = null;
        private byte[] _ciphertext = null;

        private Builder() {
        }

        public Builder keyProviderId(String keyProviderId) {
            _keyProviderId = keyProviderId;
            return this;
        }

        public Builder keyProviderInfo(byte[] keyProviderInfo) {
            _keyProviderInfo = keyProviderInfo == null ? null : keyProviderInfo.clone();
            return this;
        }

        public Builder ciphertext(byte[] ciphertext) {
            _ciphertext = ciphertext == null ? null : ciphertext.clone();
            return this;
        }

        public EncryptedDataKey build() {
            return new EncryptedDataKey(this);
        }
    }
}
