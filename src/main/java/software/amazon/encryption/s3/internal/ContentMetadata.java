package software.amazon.encryption.s3.internal;

import java.util.Collections;
import java.util.Map;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptedDataKey;

public class ContentMetadata {

    private final AlgorithmSuite _algorithmSuite;

    private final EncryptedDataKey _encryptedDataKey;
    private final String _encryptedDataKeyAlgorithm;
    private final Map<String, String> _encryptedDataKeyContext;

    private final byte[] _contentNonce;
    private final String _contentCipher;
    private final String _contentCipherTagLength;

    private ContentMetadata(Builder builder) {
        _algorithmSuite = builder._algorithmSuite;

        _encryptedDataKey = builder._encryptedDataKey;
        _encryptedDataKeyAlgorithm = builder._encryptedDataKeyAlgorithm;
        _encryptedDataKeyContext = builder._encryptedDataKeyContext;

        _contentNonce = builder._contentNonce;
        _contentCipher = builder._contentCipher;
        _contentCipherTagLength = builder._contentCipherTagLength;
    }

    public static Builder builder() {
        return new Builder();
    }

    public AlgorithmSuite algorithmSuite() {
        return _algorithmSuite;
    }

    public EncryptedDataKey encryptedDataKey() {
        return _encryptedDataKey;
    }

    public String encryptedDataKeyAlgorithm() {
        return _encryptedDataKeyAlgorithm;
    }

    public Map<String, String> encryptedDataKeyContext() {
        return _encryptedDataKeyContext;
    }

    public byte[] contentNonce() {
        return _contentNonce;
    }

    public String contentCipher() {
        return _contentCipher;
    }

    public String contentCipherTagLength() {
        return _contentCipherTagLength;
    }

    public static class Builder {
        private AlgorithmSuite _algorithmSuite;

        private EncryptedDataKey _encryptedDataKey;
        private String _encryptedDataKeyAlgorithm;
        private Map<String, String> _encryptedDataKeyContext;

        private byte[] _contentNonce;
        private String _contentCipher;
        private String _contentCipherTagLength;

        private Builder () {

        }

        public Builder algorithmSuite(AlgorithmSuite algorithmSuite) {
            _algorithmSuite = algorithmSuite;
            return this;
        }

        public Builder encryptedDataKey(EncryptedDataKey encryptedDataKey) {
            _encryptedDataKey = encryptedDataKey;
            return this;
        }

        public Builder encryptedDataKeyAlgorithm(String encryptedDataKeyAlgorithm) {
            _encryptedDataKeyAlgorithm = encryptedDataKeyAlgorithm;
            return this;
        }

        public Builder encryptedDataKeyContext(Map<String, String> encryptedDataKeyContext) {
            _encryptedDataKeyContext = Collections.unmodifiableMap(encryptedDataKeyContext);
            return this;
        }

        public Builder contentNonce(byte[] contentNonce) {
            _contentNonce = contentNonce.clone();
            return this;
        }


        public ContentMetadata build() { return new ContentMetadata(this); }
    }

}
