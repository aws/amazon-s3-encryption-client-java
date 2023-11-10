// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.interceptor.ExecutionAttribute;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.services.s3.DelegatingS3Client;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.AbortMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.AbortMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
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
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.GetEncryptedObjectPipeline;
import software.amazon.encryption.s3.internal.MultiFileOutputStream;
import software.amazon.encryption.s3.internal.MultipartUploadObjectPipeline;
import software.amazon.encryption.s3.internal.PutEncryptedObjectPipeline;
import software.amazon.encryption.s3.internal.UploadObjectObserver;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DefaultCryptoMaterialsManager;
import software.amazon.encryption.s3.materials.Keyring;
import software.amazon.encryption.s3.materials.KmsKeyring;
import software.amazon.encryption.s3.materials.MultipartConfiguration;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;
import software.amazon.encryption.s3.materials.RsaKeyring;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;

import static software.amazon.encryption.s3.S3EncryptionClientUtilities.DEFAULT_BUFFER_SIZE_BYTES;
import static software.amazon.encryption.s3.S3EncryptionClientUtilities.INSTRUCTION_FILE_SUFFIX;
import static software.amazon.encryption.s3.S3EncryptionClientUtilities.MAX_ALLOWED_BUFFER_SIZE_BYTES;
import static software.amazon.encryption.s3.S3EncryptionClientUtilities.MIN_ALLOWED_BUFFER_SIZE_BYTES;
import static software.amazon.encryption.s3.S3EncryptionClientUtilities.instructionFileKeysToDelete;
import static software.amazon.encryption.s3.internal.ApiNameVersion.API_NAME_INTERCEPTOR;

/**
 * This client is a drop-in replacement for the S3 client. It will automatically encrypt objects
 * on putObject and decrypt objects on getObject using the provided encryption key(s).
 */
public class S3EncryptionClient extends DelegatingS3Client {

    // Used for request-scoped encryption contexts for supporting keys
    public static final ExecutionAttribute<Map<String, String>> ENCRYPTION_CONTEXT = new ExecutionAttribute<>("EncryptionContext");
    public static final ExecutionAttribute<MultipartConfiguration> CONFIGURATION = new ExecutionAttribute<>("MultipartConfiguration");

    private final S3Client _wrappedClient;
    private final S3AsyncClient _wrappedAsyncClient;
    private final CryptographicMaterialsManager _cryptoMaterialsManager;
    private final SecureRandom _secureRandom;
    private final boolean _enableLegacyUnauthenticatedModes;
    private final boolean _enableDelayedAuthenticationMode;
    private final boolean _enableMultipartPutObject;
    private final MultipartUploadObjectPipeline _multipartPipeline;
    private final long _bufferSize;

    private S3EncryptionClient(Builder builder) {
        super(builder._wrappedClient);
        _wrappedClient = builder._wrappedClient;
        _wrappedAsyncClient = builder._wrappedAsyncClient;
        _cryptoMaterialsManager = builder._cryptoMaterialsManager;
        _secureRandom = builder._secureRandom;
        _enableLegacyUnauthenticatedModes = builder._enableLegacyUnauthenticatedModes;
        _enableDelayedAuthenticationMode = builder._enableDelayedAuthenticationMode;
        _enableMultipartPutObject = builder._enableMultipartPutObject;
        _multipartPipeline = builder._multipartPipeline;
        _bufferSize = builder._bufferSize;
    }

    /**
     * Creates a builder that can be used to configure and create a {@link S3EncryptionClient}.
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
    public static Consumer<AwsRequestOverrideConfiguration.Builder> withAdditionalConfiguration(Map<String, String> encryptionContext) {
        return builder ->
                builder.putExecutionAttribute(S3EncryptionClient.ENCRYPTION_CONTEXT, encryptionContext);
    }

    /**
     * Attaches multipart configuration to a request. Must be used as a parameter to
     * {@link S3Request#overrideConfiguration()} in the request.
     * @param multipartConfiguration the {@link MultipartConfiguration} instance to use
     * @return Consumer for use in overrideConfiguration()
     */
    public static Consumer<AwsRequestOverrideConfiguration.Builder> withAdditionalConfiguration(MultipartConfiguration multipartConfiguration) {
        return builder ->
                builder.putExecutionAttribute(S3EncryptionClient.CONFIGURATION, multipartConfiguration);
    }


    /**
     * Attaches encryption context and multipart configuration to a request.
     * * Must be used as a parameter to
     * {@link S3Request#overrideConfiguration()} in the request.
     * Encryption context can be used to enforce authentication of ciphertext.
     * The same encryption context used to encrypt MUST be provided on decrypt.
     * Encryption context is only supported with KMS keys.
     * @param encryptionContext the encryption context to use for the request.
     * @param multipartConfiguration the {@link MultipartConfiguration} instance to use
     * @return Consumer for use in overrideConfiguration()
     */
    public static Consumer<AwsRequestOverrideConfiguration.Builder> withAdditionalConfiguration(Map<String, String> encryptionContext, MultipartConfiguration multipartConfiguration) {
        return builder ->
                builder.putExecutionAttribute(S3EncryptionClient.ENCRYPTION_CONTEXT, encryptionContext)
                        .putExecutionAttribute(S3EncryptionClient.CONFIGURATION, multipartConfiguration);
    }

    /**
     * See {@link S3EncryptionClient#putObject(PutObjectRequest, RequestBody)}.
     * <p>
     * In the S3EncryptionClient, putObject encrypts the data in the requestBody as it is
     * written to S3.
     * </p>
     * @param putObjectRequest the request instance
     * @param requestBody
     *        The content to send to the service. A {@link RequestBody} can be created using one of several factory
     *        methods for various sources of data. For example, to create a request body from a file you can do the
     *        following.
     * @return Result of the PutObject operation returned by the service.
     * @throws SdkClientException If any client side error occurs such as an IO related failure, failure to get credentials, etc.
     * @throws S3EncryptionClientException Base class for all encryption client exceptions.
     */
    @Override
    public PutObjectResponse putObject(PutObjectRequest putObjectRequest, RequestBody requestBody)
            throws AwsServiceException, SdkClientException {

        if (_enableMultipartPutObject) {
            try {
                CompleteMultipartUploadResponse completeResponse = multipartPutObject(putObjectRequest, requestBody);
                PutObjectResponse response = PutObjectResponse.builder()
                        .eTag(completeResponse.eTag())
                        .build();
                return response;
            } catch (Throwable e) {
                throw new S3EncryptionClientException("Exception while performing Multipart Upload PutObject", e);
            }
        }
        PutEncryptedObjectPipeline pipeline = PutEncryptedObjectPipeline.builder()
                .s3AsyncClient(_wrappedAsyncClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .secureRandom(_secureRandom)
                .build();

        ExecutorService singleThreadExecutor = Executors.newSingleThreadExecutor();

        try {
            CompletableFuture<PutObjectResponse> futurePut = pipeline.putObject(putObjectRequest,
                AsyncRequestBody.fromInputStream(
                    requestBody.contentStreamProvider().newStream(),
                    requestBody.optionalContentLength().orElse(-1L),
                    singleThreadExecutor
                )
            );

            PutObjectResponse response = futurePut.join();

            singleThreadExecutor.shutdown();

            return response;

        } catch (CompletionException completionException) {
            singleThreadExecutor.shutdownNow();
            throw new S3EncryptionClientException(completionException.getMessage(), completionException.getCause());
        } catch (Exception exception) {
            singleThreadExecutor.shutdownNow();
            throw new S3EncryptionClientException(exception.getMessage(), exception);
        }

    }

    /**
     * See {@link S3EncryptionClient#getObject(GetObjectRequest, ResponseTransformer)}
     * <p>
     * In the S3EncryptionClient, getObject decrypts the data as it is read from S3.
     * </p>
     * @param getObjectRequest the request instance
     * @param responseTransformer
     *        Functional interface for processing the streamed response content. The unmarshalled GetObjectResponse and
     *        an InputStream to the response content are provided as parameters to the callback. The callback may return
     *        a transformed type which will be the return value of this method. See
     *        {@link software.amazon.awssdk.core.sync.ResponseTransformer} for details on implementing this interface
     *        and for links to pre-canned implementations for common scenarios like downloading to a file.
     * @return The transformed result of the ResponseTransformer.
     * @throws SdkClientException If any client side error occurs such as an IO related failure, failure to get credentials, etc.
     * @throws S3EncryptionClientException Base class for all encryption client exceptions.
     */
    @Override
    public <T> T getObject(GetObjectRequest getObjectRequest,
                           ResponseTransformer<GetObjectResponse, T> responseTransformer)
            throws AwsServiceException, SdkClientException {

        GetEncryptedObjectPipeline pipeline = GetEncryptedObjectPipeline.builder()
                .s3AsyncClient(_wrappedAsyncClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .enableLegacyUnauthenticatedModes(_enableLegacyUnauthenticatedModes)
                .enableDelayedAuthentication(_enableDelayedAuthenticationMode)
                .bufferSize(_bufferSize)
                .build();

        try {
            ResponseInputStream<GetObjectResponse> joinFutureGet = pipeline.getObject(getObjectRequest, AsyncResponseTransformer.toBlockingInputStream()).join();
            return responseTransformer.transform(joinFutureGet.response(), AbortableInputStream.create(joinFutureGet));
        } catch (CompletionException e) {
            throw new S3EncryptionClientException(e.getCause().getMessage(), e.getCause());
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to transform response.", e);
        }
    }

    private CompleteMultipartUploadResponse multipartPutObject(PutObjectRequest request, RequestBody requestBody) throws Throwable {
        // Similar logic exists in the MultipartUploadObjectPipeline,
        // but the request types do not match so refactoring is not possible
        final long contentLength;
        if (request.contentLength() != null) {
            if (requestBody.optionalContentLength().isPresent() && !request.contentLength().equals(requestBody.optionalContentLength().get())) {
                // if the contentLength values do not match, throw an exception, since we don't know which is correct
                throw new S3EncryptionClientException("The contentLength provided in the request object MUST match the " +
                        "contentLength in the request body");
            } else if (!requestBody.optionalContentLength().isPresent()) {
                // no contentLength in request body, use the one in request
                contentLength = request.contentLength();
            } else {
                // only remaining case is when the values match, so either works here
                contentLength = request.contentLength();
            }
        } else {
            contentLength = requestBody.optionalContentLength().orElse(-1L);
        }

        if (contentLength > AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherMaxContentLengthBytes()) {
            throw new S3EncryptionClientException("The contentLength of the object you are attempting to encrypt exceeds" +
                    "the maximum length allowed for GCM encryption.");
        }

        MultipartConfiguration multipartConfiguration;
        // If MultipartConfiguration is null, Initialize MultipartConfiguration
        if (request.overrideConfiguration().isPresent()) {
            multipartConfiguration = request.overrideConfiguration().get()
                    .executionAttributes()
                    .getOptionalAttribute(S3EncryptionClient.CONFIGURATION)
                    .orElse(MultipartConfiguration.builder().build());
        } else {
            multipartConfiguration = MultipartConfiguration.builder().build();
        }

        ExecutorService es = multipartConfiguration.executorService();
        if (es == null) {
            throw new S3EncryptionClientException("ExecutorService should not be null, Please initialize during MultipartConfiguration");
        }

        UploadObjectObserver observer = multipartConfiguration.uploadObjectObserver();
        if (observer == null) {
            throw new S3EncryptionClientException("UploadObjectObserver should not be null, Please initialize during MultipartConfiguration");
        }

        observer.init(request, _wrappedAsyncClient, this, es);
        final String uploadId = observer.onUploadCreation(request);
        final List<CompletedPart> partETags = new ArrayList<>();

        MultiFileOutputStream outputStream = multipartConfiguration.multiFileOutputStream();
        if (outputStream == null) {
            throw new S3EncryptionClientException("MultiFileOutputStream should not be null, Please initialize during MultipartConfiguration");
        }

        try {
            // initialize the multi-file output stream
            outputStream.init(observer, multipartConfiguration.partSize(), multipartConfiguration.diskLimit());
            // Kicks off the encryption-upload pipeline;
            // Note outputStream is automatically closed upon method completion.
            _multipartPipeline.putLocalObject(requestBody, uploadId, outputStream);
            // block till all part have been uploaded
            for (Future<Map<Integer, UploadPartResponse>> future : observer.futures()) {
                Map<Integer, UploadPartResponse> partResponseMap = future.get();
                partResponseMap.forEach((partNumber, uploadPartResponse) -> partETags.add(CompletedPart.builder()
                        .partNumber(partNumber)
                        .eTag(uploadPartResponse.eTag())
                        .build()));
            }
        } catch (IOException | InterruptedException | ExecutionException | RuntimeException | Error ex) {
            throw onAbort(observer, ex);
        } finally {
            if (multipartConfiguration.usingDefaultExecutorService()) {
                // shut down the thread pool if it was created by the encryption client
                es.shutdownNow();
            }
            // delete left-over temp files
            outputStream.cleanup();
        }
        // Complete upload
        return observer.onCompletion(partETags);
    }

    private <T extends Throwable> T onAbort(UploadObjectObserver observer, T t) {
        observer.onAbort();
        throw new S3EncryptionClientException(t.getMessage(), t);
    }

    /**
     * See {@link S3Client#deleteObject(DeleteObjectRequest)}.
     * <p>
     * In the S3 Encryption Client, deleteObject also deletes the instruction file,
     * if present.
     * </p>
     * @param deleteObjectRequest the request instance
     * @return Result of the DeleteObject operation returned by the service.
     */
    @Override
    public DeleteObjectResponse deleteObject(DeleteObjectRequest deleteObjectRequest) throws AwsServiceException,
            SdkClientException {
        DeleteObjectRequest actualRequest = deleteObjectRequest.toBuilder()
                .overrideConfiguration(API_NAME_INTERCEPTOR)
                .build();

        try {
            // Delete the object
            DeleteObjectResponse deleteObjectResponse = _wrappedAsyncClient.deleteObject(actualRequest).join();
            // If Instruction file exists, delete the instruction file as well.
            String instructionObjectKey = deleteObjectRequest.key() + INSTRUCTION_FILE_SUFFIX;
            _wrappedAsyncClient.deleteObject(builder -> builder
                    .overrideConfiguration(API_NAME_INTERCEPTOR)
                    .bucket(deleteObjectRequest.bucket())
                    .key(instructionObjectKey)).join();
            // Return original deletion
            return deleteObjectResponse;
        } catch (CompletionException e) {
            throw new S3EncryptionClientException(e.getCause().getMessage(), e.getCause());
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to delete object.", e);
        }
    }

    /**
     * See {@link S3Client#deleteObjects(DeleteObjectsRequest)}.
     * <p>
     * In the S3 Encryption Client, deleteObjects also deletes the instruction file(s),
     * if present.
     * </p>
     * @param deleteObjectsRequest the request instance
     * @return Result of the DeleteObjects operation returned by the service.
     */
    @Override
    public DeleteObjectsResponse deleteObjects(DeleteObjectsRequest deleteObjectsRequest) throws AwsServiceException,
            SdkClientException {
        DeleteObjectsRequest actualRequest = deleteObjectsRequest.toBuilder()
                .overrideConfiguration(API_NAME_INTERCEPTOR)
                .build();
        try {
            // Delete the objects
            DeleteObjectsResponse deleteObjectsResponse = _wrappedAsyncClient.deleteObjects(actualRequest).join();
            // If Instruction files exists, delete the instruction files as well.
            List<ObjectIdentifier> deleteObjects = instructionFileKeysToDelete(deleteObjectsRequest);
            _wrappedAsyncClient.deleteObjects(DeleteObjectsRequest.builder()
                    .overrideConfiguration(API_NAME_INTERCEPTOR)
                    .bucket(deleteObjectsRequest.bucket())
                    .delete(builder -> builder.objects(deleteObjects))
                    .build()).join();
            return deleteObjectsResponse;
        } catch (CompletionException e) {
            throw new S3EncryptionClientException(e.getCause().getMessage(), e.getCause());
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to delete objects.", e);
        }
    }

    /**
     * See {@link S3Client#createMultipartUpload(CreateMultipartUploadRequest)}
     * <p>
     * In the S3EncryptionClient, createMultipartUpload creates an encrypted
     * multipart upload. Parts MUST be uploaded sequentially.
     * See {@link S3EncryptionClient#uploadPart(UploadPartRequest, RequestBody)} for details.
     * </p>
     * @param request the request instance
     * @return Result of the CreateMultipartUpload operation returned by the service.
     */
    @Override
    public CreateMultipartUploadResponse createMultipartUpload(CreateMultipartUploadRequest request) {
        try {
            return _multipartPipeline.createMultipartUpload(request);
        } catch (CompletionException e) {
            throw new S3EncryptionClientException(e.getCause().getMessage(), e.getCause());
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to create Multipart upload.", e);
        }
    }

    /**
     * See {@link S3Client#uploadPart(UploadPartRequest, RequestBody)}
     *
     * <b>NOTE:</b> Because the encryption process requires context from block
     * N-1 in order to encrypt block N, parts uploaded with the
     * S3EncryptionClient (as opposed to the normal S3Client) must
     * be uploaded serially, and in order. Otherwise, the previous encryption
     * context isn't available to use when encrypting the current part.
     * @param request the request instance
     * @return Result of the UploadPart operation returned by the service.
     */
    @Override
    public UploadPartResponse uploadPart(UploadPartRequest request, RequestBody requestBody)
            throws AwsServiceException, SdkClientException {
        try {
            return _multipartPipeline.uploadPart(request, requestBody);
        } catch (CompletionException e) {
            throw new S3EncryptionClientException(e.getCause().getMessage(), e.getCause());
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to upload part.", e);
        }
    }

    /**
     * See {@link S3Client#completeMultipartUpload(CompleteMultipartUploadRequest)}
     * @param request the request instance
     * @return Result of the CompleteMultipartUpload operation returned by the service.
     */
    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(CompleteMultipartUploadRequest request)
            throws AwsServiceException, SdkClientException {
        try {
            return _multipartPipeline.completeMultipartUpload(request);
        } catch (CompletionException e) {
            throw new S3EncryptionClientException(e.getCause().getMessage(), e.getCause());
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to complete Multipart upload.", e);
        }
    }

    /**
     * See {@link S3Client#abortMultipartUpload(AbortMultipartUploadRequest)}
     * @param request the request instance
     * @return Result of the AbortMultipartUpload operation returned by the service.
     */
    @Override
    public AbortMultipartUploadResponse abortMultipartUpload(AbortMultipartUploadRequest request)
            throws AwsServiceException, SdkClientException {
        try {
            return _multipartPipeline.abortMultipartUpload(request);
        } catch (CompletionException e) {
            throw new S3EncryptionClientException(e.getCause().getMessage(), e.getCause());
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to abort Multipart upload.", e);
        }
    }

    /**
     * Closes the wrapped clients.
     */
    @Override
    public void close() {
        _wrappedClient.close();
        _wrappedAsyncClient.close();
    }

    // This is very similar to the S3EncryptionClient builder
    // Make sure to keep both clients in mind when adding new builder options
    public static class Builder {
        // The non-encrypted APIs will use a default client.
        private S3Client _wrappedClient;
        private S3AsyncClient _wrappedAsyncClient;

        private MultipartUploadObjectPipeline _multipartPipeline;
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        private Keyring _keyring;
        private SecretKey _aesKey;
        private PartialRsaKeyPair _rsaKeyPair;
        private String _kmsKeyId;
        private boolean _enableLegacyWrappingAlgorithms = false;
        private boolean _enableDelayedAuthenticationMode = false;
        private boolean _enableMultipartPutObject = false;
        private Provider _cryptoProvider = null;
        private SecureRandom _secureRandom = new SecureRandom();
        private boolean _enableLegacyUnauthenticatedModes = false;
        private long _bufferSize = -1L;

        private Builder() {
        }

        /**
         * Sets the wrappedClient to be used for non-cryptographic operations.
         */
        /*
         * Note that this does NOT create a defensive clone of S3Client. Any modifications made to the wrapped
         * S3Client will be reflected in this Builder.
         */
        @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "Pass mutability into wrapping client")
        public Builder wrappedClient(S3Client _wrappedClient) {
            if (_wrappedClient instanceof S3EncryptionClient) {
                throw new S3EncryptionClientException("Cannot use S3EncryptionClient as wrapped client");
            }
            this._wrappedClient = _wrappedClient;
            return this;
        }

        /**
         * Sets the wrappedAsyncClient to be used for cryptographic operations.
         */
        /*
         * Note that this does NOT create a defensive clone of S3AsyncClient. Any modifications made to the wrapped
         * S3AsyncClient will be reflected in this Builder.
         */
        @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "Pass mutability into wrapping client")
        public Builder wrappedAsyncClient(S3AsyncClient _wrappedAsyncClient) {
            if (_wrappedAsyncClient instanceof S3AsyncEncryptionClient) {
                throw new S3EncryptionClientException("Cannot use S3AsyncEncryptionClient as wrapped client");
            }

            this._wrappedAsyncClient = _wrappedAsyncClient;
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
         * Validates and builds the S3EncryptionClient according
         * to the configuration options passed to the Builder object.
         * @return an instance of the S3EncryptionClient
         */
        public S3EncryptionClient build() {
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
                _wrappedClient = S3Client.create();
            }

            if (_wrappedAsyncClient == null) {
                _wrappedAsyncClient = S3AsyncClient.create();
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

            _multipartPipeline = MultipartUploadObjectPipeline.builder()
                    .s3AsyncClient(_wrappedAsyncClient)
                    .cryptoMaterialsManager(_cryptoMaterialsManager)
                    .secureRandom(_secureRandom)
                    .build();

            return new S3EncryptionClient(this);
        }
    }
}
