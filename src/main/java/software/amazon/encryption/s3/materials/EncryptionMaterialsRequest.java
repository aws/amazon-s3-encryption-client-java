package software.amazon.encryption.s3.materials;

import java.util.Collections;
import java.util.Map;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

final public class EncryptionMaterialsRequest {

    private final PutObjectRequest _s3Request;
    private final Map<String, String> _encryptionContext;

    private EncryptionMaterialsRequest(Builder builder) {
        this._s3Request = builder._s3Request;
        this._encryptionContext = builder._encryptionContext;
    }

    static public Builder builder() {
        return new Builder();
    }

    public PutObjectRequest s3Request() {
        return _s3Request;
    }

    public Map<String, String> encryptionContext() {
        return _encryptionContext;
    }

    static public class Builder {

        public PutObjectRequest _s3Request = null;
        private Map<String, String> _encryptionContext = Collections.emptyMap();

        private Builder() {
        }

        public Builder s3Request(PutObjectRequest s3Request) {
            _s3Request = s3Request;
            return this;
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
