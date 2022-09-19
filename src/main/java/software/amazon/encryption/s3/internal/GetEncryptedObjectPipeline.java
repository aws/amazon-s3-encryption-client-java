package software.amazon.encryption.s3.internal;

import java.io.InputStream;
import java.util.Collections;
import java.util.List;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.legacy.internal.AesCbcContentStrategy;
import software.amazon.encryption.s3.legacy.internal.RangedGetAesCbcContentStrategy;
import software.amazon.encryption.s3.legacy.internal.RangedGetAesGcmContentStrategy;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DecryptMaterialsRequest;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptedDataKey;

/**
 * This class will determine the necessary mechanisms to decrypt objects returned from S3.
 * Due to supporting various legacy modes, this is not a predefined pipeline like
 * PutEncryptedObjectPipeline. There are several branches in this graph that are determined as more
 * information is available from the returned object.
 */
public class GetEncryptedObjectPipeline {

    private final S3Client _s3Client;
    private final CryptographicMaterialsManager _cryptoMaterialsManager;
    private final boolean _enableLegacyModes;

    public static Builder builder() { return new Builder(); }

    private GetEncryptedObjectPipeline(Builder builder) {
        this._s3Client = builder._s3Client;
        this._cryptoMaterialsManager = builder._cryptoMaterialsManager;
        this._enableLegacyModes = builder._enableLegacyModes;
    }

    public <T> T getObject(GetObjectRequest getObjectRequest,
            ResponseTransformer<GetObjectResponse, T> responseTransformer) {
        ResponseInputStream<GetObjectResponse> objectStream = _s3Client.getObject(
                getObjectRequest);
        GetObjectResponse getObjectResponse = objectStream.response();
        ContentMetadata contentMetadata = ContentMetadataStrategy.decode(_s3Client, getObjectRequest, getObjectResponse);

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

        ContentDecryptionStrategy contentDecryptionStrategy = selectContentDecryptionStrategy(algorithmSuite, materials);

        final InputStream plaintext = contentDecryptionStrategy.decryptContent(contentMetadata, materials, objectStream);

        try {
            return responseTransformer.transform(getObjectResponse,
                    AbortableInputStream.create(plaintext));
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to transform response.", e);
        }
    }

    /**
     * Select which content decryption strategy to use based on the algorithm suite
     * and whether the request is using range get or not.
     * @param algorithmSuite
     * @param materials
     */
    private ContentDecryptionStrategy selectContentDecryptionStrategy(final AlgorithmSuite algorithmSuite, final DecryptionMaterials materials) {
        if (materials.s3Request().range() != null) {
            if (!_enableLegacyModes) {
                throw new S3EncryptionClientException("Enable legacy modes in order to use range gets.");
            }
            switch (algorithmSuite) {
                case ALG_AES_256_CBC_IV16_NO_KDF:
                    return new RangedGetAesCbcContentStrategy();
                case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
                    return new RangedGetAesGcmContentStrategy();
            }
        }
        switch (algorithmSuite) {
            case ALG_AES_256_CBC_IV16_NO_KDF:
                return AesCbcContentStrategy.builder().build();
            case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
                return AesGcmContentStrategy.builder().build();
        }
        throw new S3EncryptionClientException("Invalid algorithm choice specified!");
    }

    public static class Builder {
        private S3Client _s3Client;
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        private boolean _enableLegacyModes;

        private Builder() {}

        public Builder s3Client(S3Client s3Client) {
            this._s3Client = s3Client;
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

        public GetEncryptedObjectPipeline build() {
            return new GetEncryptedObjectPipeline(this);
        }
    }
}
