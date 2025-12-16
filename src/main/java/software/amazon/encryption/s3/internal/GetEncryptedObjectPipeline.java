// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import static software.amazon.encryption.s3.internal.ApiNameVersion.API_NAME_INTERCEPTOR;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.async.SdkPublisher;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.CommitmentPolicy;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.legacy.internal.AesCtrUtils;
import software.amazon.encryption.s3.legacy.internal.RangedGetUtils;
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
    private final S3AsyncClient _s3AsyncClient;
    private final CryptographicMaterialsManager _cryptoMaterialsManager;
    private final boolean _enableLegacyUnauthenticatedModes;
    private final boolean _enableDelayedAuthentication;
    private final long _bufferSize;
    private final InstructionFileConfig _instructionFileConfig;
    private final CommitmentPolicy _commitmentPolicy;

    public static Builder builder() {
        return new Builder();
    }

    private GetEncryptedObjectPipeline(Builder builder) {
        this._s3AsyncClient = builder._s3AsyncClient;
        this._cryptoMaterialsManager = builder._cryptoMaterialsManager;
        this._enableLegacyUnauthenticatedModes = builder._enableLegacyUnauthenticatedModes;
        this._enableDelayedAuthentication = builder._enableDelayedAuthentication;
        this._bufferSize = builder._bufferSize;
        this._instructionFileConfig = builder._instructionFileConfig;
        this._commitmentPolicy = builder._commitmentPolicy;
    }

    public <T> CompletableFuture<T> getObject(GetObjectRequest getObjectRequest, AsyncResponseTransformer<GetObjectResponse, T> asyncResponseTransformer) {
        // In async, decryption is done within a response transformation
        //= specification/s3-encryption/decryption.md#ranged-gets
        //# The S3EC MAY support the "range" parameter on GetObject which specifies a subset of bytes to download and decrypt.
        //= specification/s3-encryption/decryption.md#ranged-gets
        //# If the S3EC supports Ranged Gets, the S3EC MUST adjust the customer-provided range to include the beginning
        //# and end of the cipher blocks for the given range.
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
        //= specification/s3-encryption/decryption.md#ranged-gets
        //= type=implication
        //# If the GetObject response contains a range, but the GetObject request does not contain a range, the S3EC
        //# MUST throw an exception.
        if (getObjectRequest.range() == null && getObjectResponse.contentRange() != null) {
            throw new S3EncryptionClientException("Content range in response but is missing from request. Ensure multipart upload is not enabled on the wrapped async client.");
        }

        AlgorithmSuite algorithmSuite = contentMetadata.algorithmSuite();
        //= specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
        //# When enabled, the S3EC MUST be able to decrypt objects encrypted with all content encryption algorithms (both legacy and fully supported).
        //= specification/s3-encryption/decryption.md#legacy-decryption
        //# The S3EC MUST NOT decrypt objects encrypted using legacy unauthenticated algorithm suites unless specifically configured to do so.
        if (!_enableLegacyUnauthenticatedModes && algorithmSuite.isLegacy()) {
            //= specification/s3-encryption/client.md#enable-legacy-unauthenticated-modes
            //= type=implementation
            //# When disabled, the S3EC MUST NOT decrypt objects encrypted using legacy content encryption algorithms; it MUST throw an exception when attempting to decrypt an object encrypted with a legacy content encryption algorithm.
            //= specification/s3-encryption/decryption.md#legacy-decryption
            //# If the S3EC is not configured to enable legacy unauthenticated content decryption, the client MUST throw
            //# an exception when attempting to decrypt an object encrypted with a legacy unauthenticated algorithm suite.
            throw new S3EncryptionClientException("Enable legacy unauthenticated modes to use legacy content decryption: " + algorithmSuite.cipherName());
        }

        //= specification/s3-encryption/decryption.md#key-commitment
        //# The S3EC MUST validate the algorithm suite used for decryption against the key commitment policy before attempting to decrypt the content ciphertext.
        if (_commitmentPolicy.requiresDecrypt() && !algorithmSuite.isCommitting()) {
            //= specification/s3-encryption/decryption.md#key-commitment
            //# If the commitment policy requires decryption using a committing algorithm suite, and the algorithm suite
            //# associated with the object does not support key commitment, then the S3EC MUST throw an exception.
            throw new S3EncryptionClientException("Commitment policy violation, decryption requires a committing algorithm suite, " +
                    "but the object was encrypted with a non-committing algorithm. " +
                    "Configure the client to allow non-committing algorithms.");
        }

        List<EncryptedDataKey> encryptedDataKeys = Collections.singletonList(contentMetadata.encryptedDataKey());

        DecryptMaterialsRequest materialsRequest = DecryptMaterialsRequest.builder()
                .s3Request(getObjectRequest)
                .algorithmSuite(algorithmSuite)
                .encryptedDataKeys(encryptedDataKeys)
                .encryptionContext(contentMetadata.encryptionContext())
                .materialsDescription(contentMetadata.materialsDescription())
                .ciphertextLength(getObjectResponse.contentLength())
                .contentRange(getObjectRequest.range())
                .keyCommitment(contentMetadata.keyCommitment())
                .build();

        DecryptionMaterials materials = _cryptoMaterialsManager.decryptMaterials(materialsRequest);
        if (materials == null) {
            throw new S3EncryptionClientException("Decryption materials cannot be null. " +
                    "This may be caused by a misconfigured custom CMM implementation or " +
                    "a suppressed exception from metadata decoding or CMM invocation due to a network failure.");
        }
        return materials;
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
        ContentMetadataDecodingStrategy contentMetadataStrategy = new ContentMetadataDecodingStrategy(_instructionFileConfig);

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
            contentMetadata = contentMetadataStrategy.decode(getObjectRequest, response);
            materials = prepareMaterialsFromRequest(getObjectRequest, response, contentMetadata);
            wrappedAsyncResponseTransformer.onResponse(response);
        }

        @Override
        public void exceptionOccurred(Throwable error) {
            wrappedAsyncResponseTransformer.exceptionOccurred(error);
        }

        @Override
        public void onStream(SdkPublisher<ByteBuffer> ciphertextPublisher) {
            if (materials == null) {
                throw new S3EncryptionClientException("Decryption materials cannot be null. " +
                        "This may be caused by a misconfigured custom CMM implementation or " +
                        "a suppressed exception from metadata decoding or CMM invocation due to a network failure.");
            }
            long[] desiredRange = RangedGetUtils.getRange(materials.getContentRange());
            long[] cryptoRange = RangedGetUtils.getCryptoRange(materials.getContentRange());
            AlgorithmSuite algorithmSuite = materials.algorithmSuite();
            byte[] iv = contentMetadata.contentIv();
            byte[] messageId = contentMetadata.contentMessageId();
            if (algorithmSuite.isCommitting()) {
                iv = new byte[12];
                //= specification/s3-encryption/key-derivation.md#hkdf-operation
                //# When encrypting or decrypting with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
                //# the IV used in the AES-GCM content encryption/decryption MUST consist entirely of bytes with the value 0x01.
                Arrays.fill(iv, (byte) 0x01);
            }

            if (algorithmSuite == AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF
                    || algorithmSuite == AlgorithmSuite.ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY) {
                iv = AesCtrUtils.adjustIV(iv, cryptoRange[0]);
            }

            // Set MessageId or IV
            materials.setIvAndMessageId(iv, messageId);

            if (algorithmSuite.equals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF)
                    || algorithmSuite.equals(AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF)
                    || algorithmSuite.equals(AlgorithmSuite.ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY)
                    || _enableDelayedAuthentication) {
                //= specification/s3-encryption/client.md#enable-delayed-authentication
                //# When enabled, the S3EC MAY release plaintext from a stream which has not been authenticated.
                // CBC and GCM with delayed auth enabled use a standard publisher
                CipherPublisher plaintextPublisher = new CipherPublisher(ciphertextPublisher,
                        getObjectResponse.contentLength(), desiredRange, contentMetadata.contentRange(), algorithmSuite.cipherTagLengthBits(), materials, iv, messageId);
                wrappedAsyncResponseTransformer.onStream(plaintextPublisher);
            } else {
                //= specification/s3-encryption/client.md#enable-delayed-authentication
                //# When disabled the S3EC MUST NOT release plaintext from a stream which has not been authenticated.
                // Use buffered publisher for GCM when delayed auth is not enabled
                BufferedCipherPublisher plaintextPublisher = new BufferedCipherPublisher(ciphertextPublisher,
                        getObjectResponse.contentLength(), materials, iv, messageId, _bufferSize);
                wrappedAsyncResponseTransformer.onStream(plaintextPublisher);
            }
        }
    }

    public static class Builder {
        private S3AsyncClient _s3AsyncClient;
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        private boolean _enableLegacyUnauthenticatedModes;
        private boolean _enableDelayedAuthentication;
        private long _bufferSize;
        private InstructionFileConfig _instructionFileConfig;
        private CommitmentPolicy _commitmentPolicy;

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

        public Builder instructionFileConfig(InstructionFileConfig instructionFileConfig) {
            this._instructionFileConfig = instructionFileConfig;
            return this;
        }

        public Builder commitmentPolicy(CommitmentPolicy commitmentPolicy) {
            this._commitmentPolicy = commitmentPolicy;
            return this;
        }

        public GetEncryptedObjectPipeline build() {
            return new GetEncryptedObjectPipeline(this);
        }
    }
}
