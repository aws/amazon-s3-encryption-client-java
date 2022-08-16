package software.amazon.encryption.s3.internal;

import java.util.Collections;
import java.util.List;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DecryptMaterialsRequest;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptedDataKey;

public class CryptoMaterialsManagerKeyStrategy implements KeyUnwrapStrategy {

    private final CryptographicMaterialsManager _cryptoMaterialsManager;

    private CryptoMaterialsManagerKeyStrategy(Builder builder) {
        _cryptoMaterialsManager = builder._cryptoMaterialsManager;
    }

    public static Builder builder() { return new Builder(); }

    @Override
    public DecryptionMaterials unwrapKey(ContentMetadata contentMetadata) {
        List<EncryptedDataKey> encryptedDataKeys = Collections.singletonList(contentMetadata.encryptedDataKey());

        DecryptMaterialsRequest request = DecryptMaterialsRequest.builder()
                .algorithmSuite(contentMetadata.algorithmSuite())
                .encryptedDataKeys(encryptedDataKeys)
                .encryptionContext(contentMetadata.encryptedDataKeyContext())
                .build();
        return _cryptoMaterialsManager.decryptMaterials(request);
    }

    public static class Builder {
        private CryptographicMaterialsManager _cryptoMaterialsManager;

        private Builder() {}

        public Builder cryptoMaterialsManager(CryptographicMaterialsManager cryptoMaterialsManager) {
            this._cryptoMaterialsManager = cryptoMaterialsManager;
            return this;
        }

        public CryptoMaterialsManagerKeyStrategy build() {
            return new CryptoMaterialsManagerKeyStrategy(this);
        }
    }
}
