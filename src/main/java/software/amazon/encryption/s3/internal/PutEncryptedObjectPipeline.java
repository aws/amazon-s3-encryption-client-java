package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterialsRequest;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class PutEncryptedObjectPipeline {

    final private S3Client _s3Client;
    final private S3AsyncClient _s3AsyncClient;
    final private CryptographicMaterialsManager _cryptoMaterialsManager;
    final private AsyncContentEncryptionStrategy _asyncContentEncryptionStrategy;
    final private ContentEncryptionStrategy _contentEncryptionStrategy;
    final private ContentMetadataEncodingStrategy _contentMetadataEncodingStrategy;

    public static Builder builder() {
        return new Builder();
    }

    private PutEncryptedObjectPipeline(Builder builder) {
        this._s3Client = builder._s3Client;
        this._s3AsyncClient = builder._s3AsyncClient;
        this._cryptoMaterialsManager = builder._cryptoMaterialsManager;
        this._contentEncryptionStrategy = builder._contentEncryptionStrategy;
        this._asyncContentEncryptionStrategy = builder._asyncContentEncryptionStrategy;
        this._contentMetadataEncodingStrategy = builder._contentMetadataEncodingStrategy;
    }

    public CompletableFuture<PutObjectResponse> putObject(PutObjectRequest request, AsyncRequestBody requestBody) {
        // TODO: Do this in a way that fails at compile time
        if (_s3AsyncClient == null) {
            // TODO better exception, though customers should never reach
            throw new S3EncryptionClientException("No S3AsyncClient found, you have to configure it.");
        }
        EncryptionMaterialsRequest.Builder requestBuilder = EncryptionMaterialsRequest.builder()
                .s3Request(request)
                .plaintextLength(requestBody.contentLength().orElse(-1L));

        EncryptionMaterials materials = _cryptoMaterialsManager.getEncryptionMaterials(requestBuilder.build());

        EncryptedContent encryptedContent = _asyncContentEncryptionStrategy.encryptContent(materials, requestBody);


        Map<String, String> metadata = new HashMap<>(request.metadata());
        metadata = _contentMetadataEncodingStrategy.encodeMetadata(materials, encryptedContent.getNonce(), metadata);
        PutObjectRequest encryptedPutRequest = request.toBuilder().metadata(metadata).build();
        return _s3AsyncClient.putObject(encryptedPutRequest, encryptedContent.getAsyncCiphertext());
    }

    public PutObjectResponse putObject(PutObjectRequest request, RequestBody requestBody) {
        EncryptionMaterialsRequest.Builder requestBuilder = EncryptionMaterialsRequest.builder()
                .s3Request(request)
                .plaintextLength(requestBody.optionalContentLength().orElse(-1L));

        EncryptionMaterials materials = _cryptoMaterialsManager.getEncryptionMaterials(requestBuilder.build());

        EncryptedContent encryptedContent = _contentEncryptionStrategy.encryptContent(materials, requestBody.contentStreamProvider().newStream());

        Map<String, String> metadata = new HashMap<>(request.metadata());
        metadata = _contentMetadataEncodingStrategy.encodeMetadata(materials, encryptedContent.getNonce(), metadata);
        request = request.toBuilder().metadata(metadata).build();

        return _s3Client.putObject(request, RequestBody.fromInputStream(encryptedContent.getCiphertext(), encryptedContent.getCiphertextLength()));
    }

    public static class Builder {
        private S3Client _s3Client;
        private S3AsyncClient _s3AsyncClient;
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        private SecureRandom _secureRandom;
        private AsyncContentEncryptionStrategy _asyncContentEncryptionStrategy;
        private ContentEncryptionStrategy _contentEncryptionStrategy;
        private final ContentMetadataEncodingStrategy _contentMetadataEncodingStrategy = ContentMetadataStrategy.OBJECT_METADATA;


        private Builder() {
        }

        /**
         * Note that this does NOT create a defensive clone of S3Client. Any modifications made to the wrapped
         * S3Client will be reflected in this Builder.
         */
        @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "Pass mutability into wrapping client")
        public Builder s3Client(S3Client s3Client) {
            this._s3Client = s3Client;
            return this;
        }

        /**
         * Note that this does NOT create a defensive clone of S3Client. Any modifications made to the wrapped
         * S3Client will be reflected in this Builder.
         */
        @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "Pass mutability into wrapping client")
        public Builder s3AsyncClient(S3AsyncClient s3AsyncClient) {
            // TODO: This needs similar "onlyOneOrNull" logic
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
            if (_contentEncryptionStrategy == null) {
                _contentEncryptionStrategy = StreamingAesGcmContentStrategy
                        .builder()
                        .secureRandom(_secureRandom)
                        .build();
            }
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
