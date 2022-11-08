package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.IOException;
import java.security.SecureRandom;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterialsRequest;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;

public class PutEncryptedObjectPipeline {

    final private S3Client _s3Client;
    final private CryptographicMaterialsManager _cryptoMaterialsManager;
    final private SecureRandom _secureRandom;
    final private ContentEncryptionStrategy _contentEncryptionStrategy;
    final private ContentMetadataEncodingStrategy _contentMetadataEncodingStrategy;

    public static Builder builder() { return new Builder(); }

    private PutEncryptedObjectPipeline(Builder builder) {
        this._s3Client = builder._s3Client;
        this._cryptoMaterialsManager = builder._cryptoMaterialsManager;
        this._secureRandom = builder._secureRandom;
        this._contentEncryptionStrategy = builder._contentEncryptionStrategy;
        this._contentMetadataEncodingStrategy = builder._contentMetadataEncodingStrategy;
    }

    public PutObjectResponse putObject(PutObjectRequest request, RequestBody requestBody) {
        EncryptionMaterialsRequest.Builder requestBuilder = EncryptionMaterialsRequest.builder()
                .s3Request(request);

        EncryptionMaterials materials = _cryptoMaterialsManager.getEncryptionMaterials(requestBuilder.build());

        byte[] input;
        try {
            // TODO: this needs to be a stream and not a byte[]
            input = IoUtils.toByteArray(requestBody.contentStreamProvider().newStream());
        } catch (IOException e) {
            throw new S3EncryptionClientException("Cannot read input.", e);
        }
        EncryptedContent encryptedContent = _contentEncryptionStrategy.encryptContent(materials, input);

        request = _contentMetadataEncodingStrategy.encodeMetadata(materials, encryptedContent, request);

        return _s3Client.putObject(request, RequestBody.fromBytes(encryptedContent.ciphertext));
    }

    public static class Builder {
        private S3Client _s3Client;
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        private SecureRandom _secureRandom;
        private ContentEncryptionStrategy _contentEncryptionStrategy;
        private ContentMetadataEncodingStrategy _contentMetadataEncodingStrategy = ContentMetadataStrategy.OBJECT_METADATA;


        private Builder() {}

        /**
         * Note that this does NOT create a defensive clone of S3Client. Any modifications made to the wrapped
         * S3Client will be reflected in this Builder.
         */
        @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "Pass mutability into wrapping client")
        public Builder s3Client(S3Client s3Client) {
            this._s3Client = s3Client;
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

        public Builder secureRandom(SecureRandom secureRandom) {
            this._secureRandom = secureRandom;
            return this;
        }

        public PutEncryptedObjectPipeline build() {
            // Default to AesGcm since it is the only active (non-legacy) content encryption strategy
            if (_contentEncryptionStrategy == null) {
                _contentEncryptionStrategy = BufferedAesGcmContentStrategy
                    .builder()
                    .secureRandom(_secureRandom)
                    .build();
            }
            return new PutEncryptedObjectPipeline(this);
        }
    }
}
