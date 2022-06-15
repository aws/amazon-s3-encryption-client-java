package software.amazon.encryption.s3.materials;

import java.util.Collections;
import java.util.Map;

final public class EncryptionMaterialsRequest {

    private final Map<String, String> _encryptionContext;

    private EncryptionMaterialsRequest(Builder builder) {
        this._encryptionContext = builder._encryptionContext;
    }

    static public Builder builder() {
        return new Builder();
    }

    public Map<String, String> encryptionContext() {
        return _encryptionContext;
    }

    static public class Builder {

        private Map<String, String> _encryptionContext = Collections.emptyMap();

        private Builder() {
        }

        public Builder encryptionContext(Map<String, String> encryptionContext) {
            _encryptionContext = encryptionContext == null
                    ? Collections.emptyMap()
                    : Collections.unmodifiableMap(encryptionContext);
            return this;
        }

        public EncryptionMaterialsRequest build() {
            return new EncryptionMaterialsRequest(this);
        }
    }
}
