package software.amazon.encryption.s3.internal;

import java.io.IOException;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterialsRequest;

public class PutEncryptedObjectPipeline {

    final private S3Client _s3Client;
    final private CryptographicMaterialsManager _cryptoMaterialsManager;
    final private ContentEncryptionStrategy _contentEncryptionStrategy;
    final private MetadataEncodingStrategy _metadataEncodingStrategy;

    public static Builder builder() { return new Builder(); }

    private PutEncryptedObjectPipeline(Builder builder) {
        this._s3Client = builder._s3Client;
        this._cryptoMaterialsManager = builder._cryptoMaterialsManager;
        this._contentEncryptionStrategy = builder._contentEncryptionStrategy;
        this._metadataEncodingStrategy = builder._metadataEncodingStrategy;
    }

    public PutObjectResponse putObject(PutObjectRequest request, RequestBody requestBody) {
        EncryptionMaterials materials = _cryptoMaterialsManager.getEncryptionMaterials(
                EncryptionMaterialsRequest.builder()
                        .build());

        byte[] input;
        try {
            input = IoUtils.toByteArray(requestBody.contentStreamProvider().newStream());
        } catch (IOException e) {
            throw new S3EncryptionClientException("Cannot read input.", e);
        }
        EncryptedContent encryptedContent = _contentEncryptionStrategy.encryptContent(materials, input);

        request = _metadataEncodingStrategy.encodeMetadata(materials, encryptedContent, request);

        return _s3Client.putObject(request, RequestBody.fromBytes(encryptedContent.ciphertext));
    }

    public static class EncryptedContent{
        public byte[] ciphertext;
        public byte[] nonce;
    }

    @FunctionalInterface
    public interface ContentEncryptionStrategy {
        EncryptedContent encryptContent(EncryptionMaterials materials, byte[] content);
    }

    @FunctionalInterface
    public interface MetadataEncodingStrategy {
        PutObjectRequest encodeMetadata(EncryptionMaterials materials, EncryptedContent encryptedContent, PutObjectRequest request);
    }

    public static class Builder {
        private S3Client _s3Client;
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        private ContentEncryptionStrategy _contentEncryptionStrategy =
                AesGcmContentEncryptionStrategy
                        .builder()
                        .build();
        private MetadataEncodingStrategy _metadataEncodingStrategy =
                ObjectMetadataMetadataEncodingStrategy
                        .builder()
                        .build();

        private Builder() {}

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

        public Builder metadataEncodingStrategy(MetadataEncodingStrategy strategy) {
            this._metadataEncodingStrategy = strategy;
            return this;
        }

        public PutEncryptedObjectPipeline build() {
            return new PutEncryptedObjectPipeline(this);
        }
    }
}
