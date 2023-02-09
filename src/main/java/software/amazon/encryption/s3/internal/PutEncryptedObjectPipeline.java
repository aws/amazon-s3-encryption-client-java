package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterialsRequest;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class PutEncryptedObjectPipeline {

    final private S3AsyncClient _s3AsyncClient;
    final private CryptographicMaterialsManager _cryptoMaterialsManager;
    final private AsyncContentEncryptionStrategy _asyncContentEncryptionStrategy;
    final private ContentMetadataEncodingStrategy _contentMetadataEncodingStrategy;

    public static Builder builder() {
        return new Builder();
    }

    private PutEncryptedObjectPipeline(Builder builder) {
        this._s3AsyncClient = builder._s3AsyncClient;
        this._cryptoMaterialsManager = builder._cryptoMaterialsManager;
        this._asyncContentEncryptionStrategy = builder._asyncContentEncryptionStrategy;
        this._contentMetadataEncodingStrategy = builder._contentMetadataEncodingStrategy;
    }

    public CompletableFuture<PutObjectResponse> putObject(PutObjectRequest request, AsyncRequestBody requestBody) {
        EncryptionMaterialsRequest.Builder requestBuilder = EncryptionMaterialsRequest.builder()
                .s3Request(request)
                .plaintextLength(requestBody.contentLength().orElse(-1L));

        EncryptionMaterials materials = _cryptoMaterialsManager.getEncryptionMaterials(requestBuilder.build());

        EncryptedContent encryptedContent = _asyncContentEncryptionStrategy.encryptContent(materials, requestBody);

        Map<String, String> metadata = new HashMap<>(request.metadata());
        metadata = _contentMetadataEncodingStrategy.encodeMetadata(materials, encryptedContent.getNonce(), metadata);
        PutObjectRequest encryptedPutRequest = request.toBuilder().metadata(metadata).build();
        System.out.println("attempting to put " + request.key() + " with IV " + new String(encryptedContent.getNonce()));
        return _s3AsyncClient.putObject(encryptedPutRequest, encryptedContent.getAsyncCiphertext());
    }

    public static class Builder {
        private S3AsyncClient _s3AsyncClient;
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        private SecureRandom _secureRandom;
        private AsyncContentEncryptionStrategy _asyncContentEncryptionStrategy;
        private final ContentMetadataEncodingStrategy _contentMetadataEncodingStrategy = ContentMetadataStrategy.OBJECT_METADATA;


        private Builder() {
        }

        /**
         * Note that this does NOT create a defensive clone of S3Client. Any modifications made to the wrapped
         * S3Client will be reflected in this Builder.
         */
        @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "Pass mutability into wrapping client")
        public Builder s3AsyncClient(S3AsyncClient s3AsyncClient) {
            this._s3AsyncClient = s3AsyncClient;
            return this;
        }

        public Builder cryptoMaterialsManager(CryptographicMaterialsManager cryptoMaterialsManager) {
            this._cryptoMaterialsManager = cryptoMaterialsManager;
            return this;
        }

        public Builder secureRandom(SecureRandom secureRandom) {
            this._secureRandom = secureRandom;
            return this;
        }

        public PutEncryptedObjectPipeline build() {
            // Default to AesGcm since it is the only active (non-legacy) content encryption strategy
            if (_asyncContentEncryptionStrategy == null) {
                _asyncContentEncryptionStrategy = StreamingAesGcmContentStrategy
                        .builder()
                        .secureRandom(_secureRandom)
                        .build();
            }
            return new PutEncryptedObjectPipeline(this);
        }
    }
}
