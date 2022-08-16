package software.amazon.encryption.s3.internal;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.legacy.internal.AesCbcContentStrategy;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DecryptMaterialsRequest;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptedDataKey;

public class GetEncryptedObjectPipeline {

    final private S3Client _s3Client;
    final private CryptographicMaterialsManager _cryptoMaterialsManager;

    public static Builder builder() { return new Builder(); }

    private GetEncryptedObjectPipeline(Builder builder) {
        this._s3Client = builder._s3Client;
        this._cryptoMaterialsManager = builder._cryptoMaterialsManager;
    }

    public <T> T getObject(GetObjectRequest getObjectRequest,
            ResponseTransformer<GetObjectResponse, T> responseTransformer) {
        ResponseInputStream<GetObjectResponse> objectStream = _s3Client.getObject(
                getObjectRequest);
        byte[] ciphertext;
        try {
            ciphertext = IoUtils.toByteArray(objectStream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        GetObjectResponse getObjectResponse = objectStream.response();
        ContentMetadata contentMetadata = ContentMetadataStrategy.decode(_s3Client, getObjectRequest, getObjectResponse);

        AlgorithmSuite algorithmSuite = contentMetadata.algorithmSuite();
        List<EncryptedDataKey> encryptedDataKeys = Collections.singletonList(contentMetadata.encryptedDataKey());

        DecryptMaterialsRequest materialsRequest = DecryptMaterialsRequest.builder()
                .s3Request(getObjectRequest)
                .algorithmSuite(algorithmSuite)
                .encryptedDataKeys(encryptedDataKeys)
                .encryptionContext(contentMetadata.encryptedDataKeyContext())
                .build();

        DecryptionMaterials materials = _cryptoMaterialsManager.decryptMaterials(materialsRequest);

        ContentDecryptionStrategy contentDecryptionStrategy = null;
        switch (algorithmSuite) {
            case ALG_AES_256_CBC_IV16_NO_KDF:
                contentDecryptionStrategy = AesCbcContentStrategy.builder().build();
                break;
            case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
                contentDecryptionStrategy = AesGcmContentStrategy.builder().build();
                break;
        }
        byte[] plaintext = contentDecryptionStrategy.decryptContent(contentMetadata, materials, ciphertext);

        try {
            return responseTransformer.transform(getObjectResponse,
                    AbortableInputStream.create(new ByteArrayInputStream(plaintext)));
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to transform response.", e);
        }
    }

    public static class Builder {
        private S3Client _s3Client;
        private CryptographicMaterialsManager _cryptoMaterialsManager;

        private Builder() {}

        public Builder s3Client(S3Client s3Client) {
            this._s3Client = s3Client;
            return this;
        }

        public Builder cryptoMaterialsManager(CryptographicMaterialsManager cryptoMaterialsManager) {
            this._cryptoMaterialsManager = cryptoMaterialsManager;
            return this;
        }

        public GetEncryptedObjectPipeline build() {
            return new GetEncryptedObjectPipeline(this);
        }
    }
}
