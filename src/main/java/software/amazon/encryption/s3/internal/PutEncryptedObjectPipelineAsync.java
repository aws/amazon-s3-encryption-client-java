package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterialsRequest;

import java.lang.reflect.Field;
import java.util.concurrent.CompletableFuture;

public class PutEncryptedObjectPipelineAsync {

    final private S3AsyncClient _s3AsyncClient;
    final private CryptographicMaterialsManager _cryptoMaterialsManager;
    final private ContentEncryptionStrategy _contentEncryptionStrategy;
    final private ContentMetadataEncodingStrategy _contentMetadataEncodingStrategy;

    public static Builder builder() { return new Builder(); }

    private PutEncryptedObjectPipelineAsync(Builder builder) {
        this._s3AsyncClient = builder._s3AsyncClient;
        this._cryptoMaterialsManager = builder._cryptoMaterialsManager;
        this._contentEncryptionStrategy = builder._contentEncryptionStrategy;
        this._contentMetadataEncodingStrategy = builder._contentMetadataEncodingStrategy;
    }

    public CompletableFuture<PutObjectResponse> putObject(PutObjectRequest request, AsyncRequestBody asyncRequestBody)
            throws NoSuchFieldException, IllegalAccessException {
        EncryptionMaterialsRequest.Builder requestBuilder = EncryptionMaterialsRequest.builder()
                .s3Request(request);


        EncryptionMaterials materials = _cryptoMaterialsManager.getEncryptionMaterials(requestBuilder.build());

        byte[] input;
        Class obj = asyncRequestBody.getClass();
        Field field = obj.getDeclaredField("bytes");
        field.setAccessible(true);
        input = (byte[]) field.get(asyncRequestBody);

        EncryptedContent encryptedContent = _contentEncryptionStrategy.encryptContent(materials, input);

        request = _contentMetadataEncodingStrategy.encodeMetadata(materials, encryptedContent, request);

        return _s3AsyncClient.putObject(request, AsyncRequestBody.fromBytes(encryptedContent.ciphertext));
    }

    public static class Builder {
        private S3AsyncClient _s3AsyncClient;
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        // Default to AesGcm since it is the only active (non-legacy) content encryption strategy
        private ContentEncryptionStrategy _contentEncryptionStrategy =
                AesGcmContentStrategy
                        .builder()
                        .build();
        private ContentMetadataEncodingStrategy _contentMetadataEncodingStrategy = ContentMetadataStrategy.OBJECT_METADATA;

        private Builder() {}

        public Builder s3AsyncClient(S3AsyncClient s3AsyncClient) {
            this._s3AsyncClient = s3AsyncClient;
            return this;
        }

        public Builder cryptoMaterialsManager(CryptographicMaterialsManager cryptoMaterialsManager) {
            this._cryptoMaterialsManager = cryptoMaterialsManager;
            return this;
        }

        public Builder contentEncryptionStrategy(ContentEncryptionStrategy strategy) {
            this._contentEncryptionStrategy = strategy;
            return this;
        }

        public Builder metadataEncodingStrategy(ContentMetadataEncodingStrategy strategy) {
            this._contentMetadataEncodingStrategy = strategy;
            return this;
        }

        public PutEncryptedObjectPipelineAsync build() {
            return new PutEncryptedObjectPipelineAsync(this);
        }
    }
}
