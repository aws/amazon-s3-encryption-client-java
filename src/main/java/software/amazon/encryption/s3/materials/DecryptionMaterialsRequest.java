package software.amazon.encryption.s3.materials;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptionMaterials.Builder;

public class DecryptionMaterialsRequest {

    private final AlgorithmSuite _algorithmSuite;
    private final List<EncryptedDataKey> _encryptedDataKeys;
    private final Map<String, String> _encryptionContext;

    private DecryptionMaterialsRequest(Builder builder) {
        this._algorithmSuite = builder._algorithmSuite;
        this._encryptedDataKeys = builder._encryptedDataKeys;
        this._encryptionContext = builder._encryptionContext;
    }

    static public Builder builder() {
        return new Builder();
    }

    public AlgorithmSuite algorithmSuite() {
        return _algorithmSuite;
    }

    public List<EncryptedDataKey> encryptedDataKeys() {
        return _encryptedDataKeys;
    }

    public Map<String, String> encryptionContext() {
        return _encryptionContext;
    }

    static public class Builder {

        private AlgorithmSuite _algorithmSuite = AlgorithmSuite.ALG_AES_256_GCM_NO_KDF;
        private Map<String, String> _encryptionContext = Collections.emptyMap();
        private List<EncryptedDataKey> _encryptedDataKeys = Collections.emptyList();

        private Builder() {
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

        public DecryptionMaterialsRequest build() {
            return new DecryptionMaterialsRequest(this);
        }
    }
}
