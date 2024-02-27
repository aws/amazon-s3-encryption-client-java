// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.s3.DelegatingS3AsyncClient;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.internal.crt.S3CrtAsyncClient;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectsResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Request;
import software.amazon.encryption.s3.internal.GetEncryptedObjectPipeline;
import software.amazon.encryption.s3.internal.NoRetriesAsyncRequestBody;
import software.amazon.encryption.s3.internal.PutEncryptedObjectPipeline;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DefaultCryptoMaterialsManager;
import software.amazon.encryption.s3.materials.Keyring;
import software.amazon.encryption.s3.materials.KmsKeyring;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;
import software.amazon.encryption.s3.materials.RsaKeyring;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Function;

import static software.amazon.encryption.s3.S3EncryptionClientUtilities.DEFAULT_BUFFER_SIZE_BYTES;
import static software.amazon.encryption.s3.S3EncryptionClientUtilities.MAX_ALLOWED_BUFFER_SIZE_BYTES;
import static software.amazon.encryption.s3.S3EncryptionClientUtilities.MIN_ALLOWED_BUFFER_SIZE_BYTES;
import static software.amazon.encryption.s3.internal.ApiNameVersion.API_NAME_INTERCEPTOR;

/**
 * This client is a drop-in replacement for the S3 Async client. It will automatically encrypt objects
 * on putObject and decrypt objects on getObject using the provided encryption key(s).
 */
public class S3AsyncEncryptionClient extends DelegatingS3AsyncClient {

    private final S3AsyncClient _wrappedClient;
    private final CryptographicMaterialsManager _cryptoMaterialsManager;
    private final SecureRandom _secureRandom;
    private final boolean _enableLegacyUnauthenticatedModes;
    private final boolean _enableDelayedAuthenticationMode;
    private final boolean _enableMultipartPutObject;
    private final long _bufferSize;

    private S3AsyncEncryptionClient(Builder builder) {
        super(builder._wrappedClient);
        _wrappedClient = builder._wrappedClient;
        _cryptoMaterialsManager = builder._cryptoMaterialsManager;
        _secureRandom = builder._secureRandom;
        _enableLegacyUnauthenticatedModes = builder._enableLegacyUnauthenticatedModes;
        _enableDelayedAuthenticationMode = builder._enableDelayedAuthenticationMode;
        _enableMultipartPutObject = builder._enableMultipartPutObject;
        _bufferSize = builder._bufferSize;
    }

    /**
     * Creates a builder that can be used to configure and create a {@link S3AsyncEncryptionClient}.
     */
    public static Builder builder() {
        return new Builder();
    }


    /**
     * Attaches encryption context to a request. Must be used as a parameter to
     * {@link S3Request#overrideConfiguration()} in the request.
     * Encryption context can be used to enforce authentication of ciphertext.
     * The same encryption context used to encrypt MUST be provided on decrypt.
     * Encryption context is only supported with KMS keys.
     * @param encryptionContext the encryption context to use for the request.
     * @return Consumer for use in overrideConfiguration()
     */
    public static Consumer<AwsRequestOverrideConfiguration.Builder> withAdditionalEncryptionContext(Map<String, String> encryptionContext) {
        return builder ->
                builder.putExecutionAttribute(S3EncryptionClient.ENCRYPTION_CONTEXT, encryptionContext);
    }

    /**
     * See {@link S3AsyncClient#putObject(PutObjectRequest, AsyncRequestBody)}.
     * <p>
     * In the S3AsyncEncryptionClient, putObject encrypts the data in the requestBody as it is
     * written to S3.
     * </p>
     * @param putObjectRequest the request instance
     * @param requestBody
     *        Functional interface that can be implemented to produce the request content in a non-blocking manner. The
     *        size of the content is expected to be known up front. See {@link AsyncRequestBody} for specific details on
     *        implementing this interface as well as links to precanned implementations for common scenarios like
     *        uploading from a file.
     * @return A Java Future containing the result of the PutObject operation returned by the service.
     *         <p>
     *         The CompletableFuture returned by this method can be completed exceptionally with the following
     *         exceptions.
     *         <ul>
     *         <li>SdkException Base class for all exceptions that can be thrown by the SDK (both service and client).
     *         Can be used for catch all scenarios.</li>
     *         <li>SdkClientException If any client side error occurs such as an IO related failure, failure to get
     *         credentials, etc.</li>
     *         <li>S3EncryptionClientException Base class for all encryption client specific exceptions.</li>
     *         </ul>
     */
    @Override
    public CompletableFuture<PutObjectResponse> putObject(PutObjectRequest putObjectRequest, AsyncRequestBody requestBody)
            throws AwsServiceException, SdkClientException {

        if (_enableMultipartPutObject) {
            return multipartPutObject(putObjectRequest, requestBody);
        }

        PutEncryptedObjectPipeline pipeline = PutEncryptedObjectPipeline.builder()
                .s3AsyncClient(_wrappedClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .secureRandom(_secureRandom)
                .build();

        return pipeline.putObject(putObjectRequest, requestBody);
    }

    private CompletableFuture<PutObjectResponse> multipartPutObject(PutObjectRequest putObjectRequest, AsyncRequestBody requestBody) {
        S3AsyncClient crtClient;
        if (_wrappedClient instanceof S3CrtAsyncClient) {
            // if the wrappedClient is a CRT, use it
            crtClient = _wrappedClient;
        } else {
            // else create a default one
            crtClient = S3AsyncClient.crtCreate();
        }
        PutEncryptedObjectPipeline pipeline = PutEncryptedObjectPipeline.builder()
                .s3AsyncClient(crtClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .secureRandom(_secureRandom)
                .build();
        // Ensures parts are not retried to avoid corrupting ciphertext
        AsyncRequestBody noRetryBody = new NoRetriesAsyncRequestBody(requestBody);
        return pipeline.putObject(putObjectRequest, noRetryBody);
    }

    /**
     * See {@link S3AsyncClient#getObject(GetObjectRequest, AsyncResponseTransformer)}
     * <p>
     * In the S3AsyncEncryptionClient, getObject decrypts the data as it is read from S3.
     * </p>
     * @param getObjectRequest the request instance.
     * @param asyncResponseTransformer
     *        The response transformer for processing the streaming response in a non-blocking manner. See
     *        {@link AsyncResponseTransformer} for details on how this callback should be implemented and for links to
     *        precanned implementations for common scenarios like downloading to a file.
     * @return A future to the transformed result of the AsyncResponseTransformer.
     *         <p>
     *         The CompletableFuture returned by this method can be completed exceptionally with the following
     *         exceptions.
     *         <ul>
     *         <li>NoSuchKeyException The specified key does not exist.</li>
     *         <li>InvalidObjectStateException Object is archived and inaccessible until restored.</li>
     *         <li>SdkException Base class for all exceptions that can be thrown by the SDK (both service and client).
     *         Can be used for catch all scenarios.</li>
     *         <li>SdkClientException If any client side error occurs such as an IO related failure, failure to get
     *         credentials, etc.</li>
     *         <li>S3EncryptionClientException Base class for all encryption client exceptions.</li>
     *         </ul>
     */
    @Override
    public <T> CompletableFuture<T> getObject(GetObjectRequest getObjectRequest,
                                                           AsyncResponseTransformer<GetObjectResponse, T> asyncResponseTransformer) {
        GetEncryptedObjectPipeline pipeline = GetEncryptedObjectPipeline.builder()
                .s3AsyncClient(_wrappedClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .enableLegacyUnauthenticatedModes(_enableLegacyUnauthenticatedModes)
                .enableDelayedAuthentication(_enableDelayedAuthenticationMode)
                .bufferSize(_bufferSize)
                .build();

        return pipeline.getObject(getObjectRequest, asyncResponseTransformer);
    }

    /**
     * See {@link S3AsyncClient#deleteObject(DeleteObjectRequest)}.
     * <p>
     * In the S3 Encryption Client, deleteObject also deletes the instruction file,
     * if present.
     * </p>
     * @param deleteObjectRequest the request instance
     * @return A Java Future containing the result of the DeleteObject operation returned by the service.
     */
    @Override
    public CompletableFuture<DeleteObjectResponse> deleteObject(DeleteObjectRequest deleteObjectRequest) {
        final DeleteObjectRequest actualRequest = deleteObjectRequest.toBuilder()
                .overrideConfiguration(API_NAME_INTERCEPTOR)
                .build();
        final CompletableFuture<DeleteObjectResponse> response = _wrappedClient.deleteObject(actualRequest);
        final String instructionObjectKey = deleteObjectRequest.key() + ".instruction";
        final CompletableFuture<DeleteObjectResponse> instructionResponse = _wrappedClient.deleteObject(builder -> builder
                .overrideConfiguration(API_NAME_INTERCEPTOR)
                .bucket(deleteObjectRequest.bucket())
                .key(instructionObjectKey));
        // Delete the instruction file, then delete the object
        Function<DeleteObjectResponse, DeleteObjectResponse> deletion = deleteObjectResponse ->
                response.join();
        return instructionResponse.thenApplyAsync(deletion);
    }

    /**
     * See {@link S3AsyncClient#deleteObjects(DeleteObjectsRequest)}.
     * <p>
     * In the S3 Encryption Client, deleteObjects also deletes the instruction file(s),
     * if present.
     * </p>
     * @param deleteObjectsRequest the request instance
     * @return A Java Future containing the result of the DeleteObjects operation returned by the service.
     */
    @Override
    public CompletableFuture<DeleteObjectsResponse> deleteObjects(DeleteObjectsRequest deleteObjectsRequest) throws AwsServiceException,
            SdkClientException {
        // Add the instruction file keys to the list of objects to delete
        final List<ObjectIdentifier> objectsToDelete = S3EncryptionClientUtilities.instructionFileKeysToDelete(deleteObjectsRequest);
        // Add the original objects
        objectsToDelete.addAll(deleteObjectsRequest.delete().objects());
        return _wrappedClient.deleteObjects(deleteObjectsRequest.toBuilder()
                .overrideConfiguration(API_NAME_INTERCEPTOR)
                .delete(builder -> builder.objects(objectsToDelete))
                .build());
    }

    /**
     * Closes the wrapped {@link S3AsyncClient} instance.
     */
    @Override
    public void close() {
        _wrappedClient.close();
    }

    // This is very similar to the S3EncryptionClient builder
    // Make sure to keep both clients in mind when adding new builder options
    public static class Builder {
        private S3AsyncClient _wrappedClient;
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        private Keyring _keyring;
        private SecretKey _aesKey;
        private PartialRsaKeyPair _rsaKeyPair;
        private String _kmsKeyId;
        private boolean _enableLegacyWrappingAlgorithms = false;
        private boolean _enableLegacyUnauthenticatedModes = false;
        private boolean _enableDelayedAuthenticationMode = false;
        private boolean _enableMultipartPutObject = false;
        private Provider _cryptoProvider = null;
        private SecureRandom _secureRandom = new SecureRandom();
        private long _bufferSize = -1L;

        private Builder() {
        }

        /**
         * Specifies the wrapped client to use for the actual S3 request.
         * This client will be used for all async operations.
         * You can pass any S3AsyncClient implementation (e.g. the CRT
         * client), but you cannot pass an S3AsyncEncryptionClient.
         * @param wrappedClient the client to use for S3 operations.
         * @return Returns a reference to this object so that method calls can be chained together.
         */
        /*
         * Note that this does NOT create a defensive clone of S3Client. Any modifications made to the wrapped
         * S3Client will be reflected in this Builder.
         */
        @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "Pass mutability into wrapping client")
        public Builder wrappedClient(S3AsyncClient wrappedClient) {
            if (wrappedClient instanceof S3AsyncEncryptionClient) {
                throw new S3EncryptionClientException("Cannot use S3EncryptionClient as wrapped client");
            }

            this._wrappedClient = wrappedClient;
            return this;
        }

        /**
         * Specifies the {@link CryptographicMaterialsManager} to use for managing key wrapping keys.
         * @param cryptoMaterialsManager the CMM to use
         * @return Returns a reference to this object so that method calls can be chained together.
         */
        public Builder cryptoMaterialsManager(CryptographicMaterialsManager cryptoMaterialsManager) {
            this._cryptoMaterialsManager = cryptoMaterialsManager;
            checkKeyOptions();

            return this;
        }

        /**
         * Specifies the {@link Keyring} to use for key wrapping and unwrapping.
         * @param keyring the Keyring instance to use
         * @return Returns a reference to this object so that method calls can be chained together.
         */
        public Builder keyring(Keyring keyring) {
            this._keyring = keyring;
            checkKeyOptions();

            return this;
        }

        /**
         * Specifies a "raw" AES key to use for key wrapping/unwrapping.
         * @param aesKey the AES key as a {@link SecretKey} instance
         * @return Returns a reference to this object so that method calls can be chained together.
         */
        public Builder aesKey(SecretKey aesKey) {
            this._aesKey = aesKey;
            checkKeyOptions();

            return this;
        }

        /**
         * Specifies a "raw" RSA key pair to use for key wrapping/unwrapping.
         * @param rsaKeyPair the RSA key pair as a {@link KeyPair} instance
         * @return Returns a reference to this object so that method calls can be chained together.
         */
        public Builder rsaKeyPair(KeyPair rsaKeyPair) {
            this._rsaKeyPair = new PartialRsaKeyPair(rsaKeyPair);
            checkKeyOptions();

            return this;
        }

        /**
         * Specifies a "raw" RSA key pair to use for key wrapping/unwrapping.
         * This option takes a {@link PartialRsaKeyPair} instance, which allows
         * either a public key (decryption only) or private key (encryption only)
         * rather than requiring both parts.
         * @param partialRsaKeyPair the RSA key pair as a {@link PartialRsaKeyPair} instance
         * @return Returns a reference to this object so that method calls can be chained together.
         */
        public Builder rsaKeyPair(PartialRsaKeyPair partialRsaKeyPair) {
            this._rsaKeyPair = partialRsaKeyPair;
            checkKeyOptions();

            return this;
        }

        /**
         * Specifies a KMS key to use for key wrapping/unwrapping. Any valid KMS key
         * identifier (including the full ARN or an alias ARN) is permitted. When
         * decrypting objects, the key referred to by this KMS key identifier is
         * always used.
         * @param kmsKeyId the KMS key identifier as a {@link String} instance
         * @return Returns a reference to this object so that method calls can be chained together.
         */
        public Builder kmsKeyId(String kmsKeyId) {
            this._kmsKeyId = kmsKeyId;
            checkKeyOptions();

            return this;
        }

        // We only want one way to use a key, if more than one is set, throw an error
        private void checkKeyOptions() {
            if (onlyOneNonNull(_cryptoMaterialsManager, _keyring, _aesKey, _rsaKeyPair, _kmsKeyId)) {
                return;
            }

            throw new S3EncryptionClientException("Only one may be set of: crypto materials manager, keyring, AES key, RSA key pair, KMS key id");
        }

        private boolean onlyOneNonNull(Object... values) {
            boolean haveOneNonNull = false;
            for (Object o : values) {
                if (o != null) {
                    if (haveOneNonNull) {
                        return false;
                    }

                    haveOneNonNull = true;
                }
            }

            return haveOneNonNull;
        }

        /**
         * When set to true, decryption of objects using legacy key wrapping
         * modes is enabled.
         * @param shouldEnableLegacyWrappingAlgorithms true to enable legacy wrapping algorithms
         * @return Returns a reference to this object so that method calls can be chained together.
         */
        public Builder enableLegacyWrappingAlgorithms(boolean shouldEnableLegacyWrappingAlgorithms) {
            this._enableLegacyWrappingAlgorithms = shouldEnableLegacyWrappingAlgorithms;
            return this;
        }

        /**
         * When set to true, decryption of content using legacy encryption algorithms
         * is enabled. This includes use of GetObject requests with a range, as this
         * mode is not authenticated.
         * @param shouldEnableLegacyUnauthenticatedModes true to enable legacy content algorithms
         * @return Returns a reference to this object so that method calls can be chained together.
         */
        public Builder enableLegacyUnauthenticatedModes(boolean shouldEnableLegacyUnauthenticatedModes) {
            this._enableLegacyUnauthenticatedModes = shouldEnableLegacyUnauthenticatedModes;
            return this;
        }

        /**
         * When set to true, authentication of streamed objects is delayed until the
         * entire object is read from the stream. When this mode is enabled, the consuming
         * application must support a way to invalidate any data read from the stream as
         * the tag will not be validated until the stream is read to completion, as the
         * integrity of the data cannot be ensured. See the AWS Documentation for more
         * information.
         * @param shouldEnableDelayedAuthenticationMode true to enable delayed authentication
         * @return Returns a reference to this object so that method calls can be chained together.
         */
        public Builder enableDelayedAuthenticationMode(boolean shouldEnableDelayedAuthenticationMode) {
            this._enableDelayedAuthenticationMode = shouldEnableDelayedAuthenticationMode;
            return this;
        }

        /**
         * When set to true, the putObject method will use multipart upload to perform
         * the upload. Disabled by default.
         * @param _enableMultipartPutObject true enables the multipart upload implementation of putObject
         * @return Returns a reference to this object so that method calls can be chained together.
         */
        public Builder enableMultipartPutObject(boolean _enableMultipartPutObject) {
            this._enableMultipartPutObject = _enableMultipartPutObject;
            return this;
        }

        /**
         * Sets the buffer size for safe authentication used when delayed authentication mode is disabled.
         * If buffer size is not given during client configuration, default buffer size is set to 64MiB.
         * @param bufferSize the desired buffer size in Bytes.
         * @return Returns a reference to this object so that method calls can be chained together.
         * @throws S3EncryptionClientException if the specified buffer size is outside the allowed bounds
         */
        public Builder setBufferSize(long bufferSize) {
            if (bufferSize < MIN_ALLOWED_BUFFER_SIZE_BYTES || bufferSize > MAX_ALLOWED_BUFFER_SIZE_BYTES) {
                throw new S3EncryptionClientException("Invalid buffer size: " + bufferSize + " Bytes. Buffer size must be between " + MIN_ALLOWED_BUFFER_SIZE_BYTES + " and " + MAX_ALLOWED_BUFFER_SIZE_BYTES + " Bytes.");
            }

            this._bufferSize = bufferSize;
            return this;
        }

        /**
         * Allows the user to pass an instance of {@link Provider} to be used
         * for cryptographic operations. By default, the S3 Encryption Client
         * will use the first compatible {@link Provider} in the chain. When this option
         * is used, the given provider will be used for all cryptographic operations.
         * If the provider is missing a required algorithm suite, e.g. AES-GCM, then
         * operations may fail.
         * Advanced option. Users who configure a {@link Provider} are responsible
         * for the security and correctness of the provider.
         * @param cryptoProvider the {@link Provider to always use}
         * @return Returns a reference to this object so that method calls can be chained together.
         */
        public Builder cryptoProvider(Provider cryptoProvider) {
            this._cryptoProvider = cryptoProvider;
            return this;
        }

        /**
         * Allows the user to pass an instance of {@link SecureRandom} to be used
         * for generating keys and IVs. Advanced option. Users who provide a {@link SecureRandom}
         * are responsible for the security and correctness of the {@link SecureRandom} implementation.
         * @param secureRandom the {@link SecureRandom} instance to use
         * @return Returns a reference to this object so that method calls can be chained together.
         */
        public Builder secureRandom(SecureRandom secureRandom) {
            if (secureRandom == null) {
                throw new S3EncryptionClientException("SecureRandom provided to S3EncryptionClient cannot be null");
            }
            _secureRandom = secureRandom;
            return this;
        }

        /**
         * Validates and builds the S3AsyncEncryptionClient according
         * to the configuration options passed to the Builder object.
         * @return an instance of the S3AsyncEncryptionClient
         */
        public S3AsyncEncryptionClient build() {
            if (!onlyOneNonNull(_cryptoMaterialsManager, _keyring, _aesKey, _rsaKeyPair, _kmsKeyId)) {
                throw new S3EncryptionClientException("Exactly one must be set of: crypto materials manager, keyring, AES key, RSA key pair, KMS key id");
            }

            if (_bufferSize >= 0) {
                if (_enableDelayedAuthenticationMode) {
                    throw new S3EncryptionClientException("Buffer size cannot be set when delayed authentication mode is enabled");
                }
            } else {
                _bufferSize = DEFAULT_BUFFER_SIZE_BYTES;
            }

            if (_wrappedClient == null) {
                _wrappedClient = S3AsyncClient.create();
            }

            if (_keyring == null) {
                if (_aesKey != null) {
                    _keyring = AesKeyring.builder()
                            .wrappingKey(_aesKey)
                            .enableLegacyWrappingAlgorithms(_enableLegacyWrappingAlgorithms)
                            .secureRandom(_secureRandom)
                            .build();
                } else if (_rsaKeyPair != null) {
                    _keyring = RsaKeyring.builder()
                            .wrappingKeyPair(_rsaKeyPair)
                            .enableLegacyWrappingAlgorithms(_enableLegacyWrappingAlgorithms)
                            .secureRandom(_secureRandom)
                            .build();
                } else if (_kmsKeyId != null) {
                    _keyring = KmsKeyring.builder()
                            .wrappingKeyId(_kmsKeyId)
                            .enableLegacyWrappingAlgorithms(_enableLegacyWrappingAlgorithms)
                            .secureRandom(_secureRandom)
                            .build();
                }
            }

            if (_cryptoMaterialsManager == null) {
                _cryptoMaterialsManager = DefaultCryptoMaterialsManager.builder()
                        .keyring(_keyring)
                        .cryptoProvider(_cryptoProvider)
                        .build();
            }

            return new S3AsyncEncryptionClient(this);
        }
    }
}
