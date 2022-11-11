package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.legacy.internal.RangedGetUtils;
import software.amazon.encryption.s3.legacy.internal.UnauthenticatedContentStrategy;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DecryptMaterialsRequest;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptedDataKey;

import java.io.InputStream;
import java.util.Collections;
import java.util.List;

/**
 * This class will determine the necessary mechanisms to decrypt objects returned from S3.
 * Due to supporting various legacy modes, this is not a predefined pipeline like
 * PutEncryptedObjectPipeline. There are several branches in this graph that are determined as more
 * information is available from the returned object.
 */
public class GetEncryptedObjectPipeline {

    private final S3Client _s3Client;
    private final CryptographicMaterialsManager _cryptoMaterialsManager;
    private final boolean _enableLegacyUnauthenticatedModes;
    private final boolean _enableDelayedAuthentication;

    public static Builder builder() {
        return new Builder();
    }

    private GetEncryptedObjectPipeline(Builder builder) {
        this._s3Client = builder._s3Client;
        this._cryptoMaterialsManager = builder._cryptoMaterialsManager;
        this._enableLegacyUnauthenticatedModes = builder._enableLegacyUnauthenticatedModes;
        this._enableDelayedAuthentication = builder._enableDelayedAuthentication;
    }

    public <T> T getObject(GetObjectRequest getObjectRequest,
                           ResponseTransformer<GetObjectResponse, T> responseTransformer) {
        ResponseInputStream<GetObjectResponse> objectStream;
        if (!_enableLegacyUnauthenticatedModes && getObjectRequest.range() != null) {
            throw new S3EncryptionClientException("Enable legacy unauthenticated modes to use Ranged Get.");
        }
        objectStream = _s3Client.getObject(getObjectRequest
                .toBuilder()
                .range(RangedGetUtils.getCryptoRangeAsString(getObjectRequest.range()))
                .build());

        GetObjectResponse getObjectResponse = objectStream.response();
        ContentMetadata contentMetadata = ContentMetadataStrategy.decode(_s3Client, getObjectRequest, getObjectResponse);

        AlgorithmSuite algorithmSuite = contentMetadata.algorithmSuite();
        if (!_enableLegacyUnauthenticatedModes && algorithmSuite.isLegacy()) {
            throw new S3EncryptionClientException("Enable legacy unauthenticated modes to use legacy content decryption: " + algorithmSuite.cipherName());
        }

        List<EncryptedDataKey> encryptedDataKeys = Collections.singletonList(contentMetadata.encryptedDataKey());

        DecryptMaterialsRequest materialsRequest = DecryptMaterialsRequest.builder()
                .s3Request(getObjectRequest)
                .algorithmSuite(algorithmSuite)
                .encryptedDataKeys(encryptedDataKeys)
                .encryptionContext(contentMetadata.encryptedDataKeyContext())
                .ciphertextLength(getObjectResponse.contentLength())
                .build();

        DecryptionMaterials materials = _cryptoMaterialsManager.decryptMaterials(materialsRequest);

        ContentDecryptionStrategy contentDecryptionStrategy = selectContentDecryptionStrategy(materials);
        final InputStream plaintext = contentDecryptionStrategy.decryptContent(contentMetadata, materials, objectStream);

        try {
            return responseTransformer.transform(getObjectResponse,
                    AbortableInputStream.create(plaintext));
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to transform response.", e);
        }
    }

    private ContentDecryptionStrategy selectContentDecryptionStrategy(final DecryptionMaterials materials) {
        switch (materials.algorithmSuite()) {
            case ALG_AES_256_CBC_IV16_NO_KDF:
            case ALG_AES_256_CTR_IV16_TAG16_NO_KDF:
                return UnauthenticatedContentStrategy.builder().build();
            case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
                if (_enableDelayedAuthentication) {
                    return StreamingAesGcmContentStrategy.builder().build();
                } else {
                    return BufferedAesGcmContentStrategy.builder().build();
                }
            default:
                // This should never happen in practice.
                throw new S3EncryptionClientException(String.format("No content strategy available for algorithm suite:" +
                        " %s", materials.algorithmSuite()));
        }
    }

    public static class Builder {
        private S3Client _s3Client;
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        private boolean _enableLegacyUnauthenticatedModes;
        private boolean _enableDelayedAuthentication;

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

        public Builder cryptoMaterialsManager(CryptographicMaterialsManager cryptoMaterialsManager) {
            this._cryptoMaterialsManager = cryptoMaterialsManager;
            return this;
        }

        public Builder enableLegacyUnauthenticatedModes(boolean enableLegacyUnauthenticatedModes) {
            this._enableLegacyUnauthenticatedModes = enableLegacyUnauthenticatedModes;
            return this;
        }

        public Builder enableDelayedAuthentication(boolean enableDelayedAuthentication) {
            this._enableDelayedAuthentication = enableDelayedAuthentication;
            return this;
        }

        public GetEncryptedObjectPipeline build() {
            return new GetEncryptedObjectPipeline(this);
        }
    }
}
