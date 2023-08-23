// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.async.SdkPublisher;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.legacy.internal.AesCtrUtils;
import software.amazon.encryption.s3.legacy.internal.RangedGetUtils;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DecryptMaterialsRequest;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptedDataKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static software.amazon.encryption.s3.internal.ApiNameVersion.API_NAME_INTERCEPTOR;

/**
 * This class will determine the necessary mechanisms to decrypt objects returned from S3.
 * Due to supporting various legacy modes, this is not a predefined pipeline like
 * PutEncryptedObjectPipeline. There are several branches in this graph that are determined as more
 * information is available from the returned object.
 */
public class GetEncryptedObjectPipeline {
    private final S3AsyncClient _s3AsyncClient;
    private final CryptographicMaterialsManager _cryptoMaterialsManager;
    private final boolean _enableLegacyUnauthenticatedModes;
    private final boolean _enableDelayedAuthentication;
    private final long _bufferSize;

    public static Builder builder() {
        return new Builder();
    }

    private GetEncryptedObjectPipeline(Builder builder) {
        this._s3AsyncClient = builder._s3AsyncClient;
        this._cryptoMaterialsManager = builder._cryptoMaterialsManager;
        this._enableLegacyUnauthenticatedModes = builder._enableLegacyUnauthenticatedModes;
        this._enableDelayedAuthentication = builder._enableDelayedAuthentication;
        this._bufferSize = builder._bufferSize;
    }

    public <T> CompletableFuture<T> getObject(GetObjectRequest getObjectRequest, AsyncResponseTransformer<GetObjectResponse, T> asyncResponseTransformer) {
        // In async, decryption is done within a response transformation
        String cryptoRange = RangedGetUtils.getCryptoRangeAsString(getObjectRequest.range());
        GetObjectRequest adjustedRangeRequest = getObjectRequest.toBuilder()
                .overrideConfiguration(API_NAME_INTERCEPTOR)
                .range(cryptoRange)
                .build();
        if (!_enableLegacyUnauthenticatedModes && getObjectRequest.range() != null) {
            throw new S3EncryptionClientException("Enable legacy unauthenticated modes to use Ranged Get.");
        }
        return _s3AsyncClient.getObject(adjustedRangeRequest, new DecryptingResponseTransformer<>(asyncResponseTransformer,
                getObjectRequest));
    }

    private DecryptionMaterials prepareMaterialsFromRequest(final GetObjectRequest getObjectRequest, final GetObjectResponse getObjectResponse,
                                                            final ContentMetadata contentMetadata) {
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

        return _cryptoMaterialsManager.decryptMaterials(materialsRequest);
    }

    private class DecryptingResponseTransformer<T> implements AsyncResponseTransformer<GetObjectResponse, T> {
        /**
         * This is the customer-supplied transformer. This class must
         * feed it plaintext so that it can transform the plaintext
         * into type T.
         */
        final AsyncResponseTransformer<GetObjectResponse, T> wrappedAsyncResponseTransformer;
        final GetObjectRequest getObjectRequest;
        ContentMetadata contentMetadata;
        GetObjectResponse getObjectResponse;
        DecryptionMaterials materials;

        CompletableFuture<T> resultFuture;

        DecryptingResponseTransformer(AsyncResponseTransformer<GetObjectResponse, T> wrappedAsyncResponseTransformer,
                                      GetObjectRequest getObjectRequest) {
            this.wrappedAsyncResponseTransformer = wrappedAsyncResponseTransformer;
            this.getObjectRequest = getObjectRequest;
        }

        @Override
        public CompletableFuture<T> prepare() {
            resultFuture = wrappedAsyncResponseTransformer.prepare();
            return resultFuture;
        }

        @Override
        public void onResponse(GetObjectResponse response) {
            getObjectResponse = response;
            contentMetadata = ContentMetadataStrategy.decode(getObjectRequest, response);
            materials = prepareMaterialsFromRequest(getObjectRequest, response, contentMetadata);
            wrappedAsyncResponseTransformer.onResponse(response);
        }

        @Override
        public void exceptionOccurred(Throwable error) {
            wrappedAsyncResponseTransformer.exceptionOccurred(error);
        }

        @Override
        public void onStream(SdkPublisher<ByteBuffer> ciphertextPublisher) {
            long[] desiredRange = RangedGetUtils.getRange(materials.s3Request().range());
            long[] cryptoRange = RangedGetUtils.getCryptoRange(materials.s3Request().range());
            AlgorithmSuite algorithmSuite = materials.algorithmSuite();
            SecretKey contentKey = materials.dataKey();
            final int tagLength = algorithmSuite.cipherTagLengthBits();
            byte[] iv = contentMetadata.contentIv();
            if (algorithmSuite == AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF) {
                iv = AesCtrUtils.adjustIV(iv, cryptoRange[0]);
            }
            try {
                final Cipher cipher = CryptoFactory.createCipher(algorithmSuite.cipherName(), materials.cryptoProvider());
                switch (algorithmSuite) {
                    case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
                        cipher.init(Cipher.DECRYPT_MODE, contentKey, new GCMParameterSpec(tagLength, iv));
                        break;
                    case ALG_AES_256_CTR_IV16_TAG16_NO_KDF:
                    case ALG_AES_256_CBC_IV16_NO_KDF:
                        cipher.init(Cipher.DECRYPT_MODE, contentKey, new IvParameterSpec(iv));
                        break;
                    default:
                        throw new S3EncryptionClientException("Unknown algorithm: " + algorithmSuite.cipherName());
                }

                if (algorithmSuite.equals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF)
                        || algorithmSuite.equals(AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF)
                        || _enableDelayedAuthentication) {
                    // CBC and GCM with delayed auth enabled use a standard publisher
                    CipherPublisher plaintextPublisher = new CipherPublisher(ciphertextPublisher,
                            getObjectResponse.contentLength(), desiredRange, contentMetadata.contentRange(), algorithmSuite.cipherTagLengthBits(), materials, iv);
                    wrappedAsyncResponseTransformer.onStream(plaintextPublisher);
                } else {
                    // Use buffered publisher for GCM when delayed auth is not enabled
                    BufferedCipherPublisher plaintextPublisher = new BufferedCipherPublisher(ciphertextPublisher,
                            getObjectResponse.contentLength(), materials, iv, _bufferSize);
                    wrappedAsyncResponseTransformer.onStream(plaintextPublisher);
                }

            } catch (GeneralSecurityException e) {
                throw new S3EncryptionClientException("Unable to " + algorithmSuite.cipherName() + " content decrypt.", e);
            }
        }
    }

    public static class Builder {
        private S3AsyncClient _s3AsyncClient;
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        private boolean _enableLegacyUnauthenticatedModes;
        private boolean _enableDelayedAuthentication;
        private long _bufferSize;

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

        public Builder enableLegacyUnauthenticatedModes(boolean enableLegacyUnauthenticatedModes) {
            this._enableLegacyUnauthenticatedModes = enableLegacyUnauthenticatedModes;
            return this;
        }

        public Builder bufferSize(long bufferSize) {
            this._bufferSize = bufferSize;
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
