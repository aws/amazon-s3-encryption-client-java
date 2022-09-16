package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.services.s3.S3AsyncClient;
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * This class will determine the necessary mechanisms to decrypt objects returned from S3.
 * Due to supporting various legacy modes, this is not a predefined pipeline like
 * PutEncryptedObjectPipeline & PutEncryptedObjectPipelineAsync. There are several branches in this graph that are determined as more
 * information is available from the returned object.
 */
public class GetEncryptedObjectPipelineAsync {

    private final S3AsyncClient _s3AsyncClient;
    private final CryptographicMaterialsManager _cryptoMaterialsManager;
    private final boolean _enableLegacyModes;

    public static Builder builder() { return new Builder(); }

    private GetEncryptedObjectPipelineAsync(Builder builder) {
        this._s3AsyncClient = builder._s3AsyncClient;
        this._cryptoMaterialsManager = builder._cryptoMaterialsManager;
        this._enableLegacyModes = builder._enableLegacyModes;
    }

    public <T> CompletableFuture<T> getObject(GetObjectRequest getObjectRequest,
                                        AsyncResponseTransformer<GetObjectResponse, T> responseTransformer) throws ExecutionException, InterruptedException {
        CompletableFuture<ResponseBytes<GetObjectResponse>> objectStream = _s3AsyncClient.getObject(
                getObjectRequest, AsyncResponseTransformer.toBytes());
        CompletableFuture<Object> operationCompleteFuture =
                objectStream.thenApply((objectResponse) -> {
                    byte[] ciphertext;
                    try {
                        ciphertext = IoUtils.toByteArray(objectResponse.asInputStream());
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                    GetObjectResponse getObjectResponse = objectResponse.response();
                    ContentMetadata contentMetadata = null;
                    try {
                        contentMetadata = ContentMetadataStrategyAsync.decode(_s3AsyncClient, getObjectRequest, getObjectResponse);
                    } catch (ExecutionException e) {
                        throw new RuntimeException(e);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }

                    AlgorithmSuite algorithmSuite = contentMetadata.algorithmSuite();
                    if (!_enableLegacyModes && algorithmSuite.isLegacy()) {
                        throw new S3EncryptionClientException("Enable legacy modes to use legacy content encryption: " + algorithmSuite.cipherName());
                    }

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
                        return ResponseTransformer.toBytes().transform(getObjectResponse, AbortableInputStream.create(new ByteArrayInputStream(plaintext)));
                    } catch (Exception e) {
                        throw new S3EncryptionClientException("Unable to transform response.", e);
                    }
                });
                return (CompletableFuture<T>) operationCompleteFuture;
    }
    
    public static class Builder {
        private S3AsyncClient _s3AsyncClient;
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        private boolean _enableLegacyModes;

        private Builder() {}

        public Builder s3AsyncClient(S3AsyncClient s3AsyncClient) {
            this._s3AsyncClient = s3AsyncClient;
            return this;
        }

        public Builder cryptoMaterialsManager(CryptographicMaterialsManager cryptoMaterialsManager) {
            this._cryptoMaterialsManager = cryptoMaterialsManager;
            return this;
        }

        public Builder enableLegacyModes(boolean enableLegacyModes) {
            this._enableLegacyModes = enableLegacyModes;
            return this;
        }

        public GetEncryptedObjectPipelineAsync build() {
            return new GetEncryptedObjectPipelineAsync(this);
        }
    }
}
