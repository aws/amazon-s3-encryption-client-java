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
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
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

import static software.amazon.encryption.s3.S3EncryptionClientUtilities.INSTRUCTION_FILE_SUFFIX;
import static software.amazon.encryption.s3.S3EncryptionClientUtilities.instructionFileKeysToDelete;

/**
 * This client is a drop-in replacement for the S3 client. It will automatically encrypt objects
 * on putObject and decrypt objects on getObject using the provided encryption key(s).
 */
public class S3EncryptionClient extends DelegatingS3Client {

    // Used for request-scoped encryption contexts for supporting keys
    public static final ExecutionAttribute<Map<String, String>> ENCRYPTION_CONTEXT = new ExecutionAttribute<>("EncryptionContext");
    public static final ExecutionAttribute<MultipartConfiguration> CONFIGURATION = new ExecutionAttribute<>("MultipartConfiguration");
    // TODO: Replace with UploadPartRequest.isLastPart() when launched.
    // Used for multipart uploads
    public static final ExecutionAttribute<Boolean> IS_LAST_PART = new ExecutionAttribute<>("isLastPart");

    private final S3Client _wrappedClient;
    private final S3AsyncClient _wrappedAsyncClient;
    private final CryptographicMaterialsManager _cryptoMaterialsManager;
    private final SecureRandom _secureRandom;
    private final boolean _enableLegacyUnauthenticatedModes;
    private final boolean _enableDelayedAuthenticationMode;
    private final boolean _enableMultipartPutObject;
    private final MultipartUploadObjectPipeline _multipartPipeline;

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
    }

    public static Builder builder() {
        return new Builder();
    }

    // Helper function to attach encryption contexts to a request
    public static Consumer<AwsRequestOverrideConfiguration.Builder> withAdditionalConfiguration(Map<String, String> encryptionContext) {
        return builder ->
                builder.putExecutionAttribute(S3EncryptionClient.ENCRYPTION_CONTEXT, encryptionContext);
    }

    // Helper function to attach encryption contexts to a request
    public static Consumer<AwsRequestOverrideConfiguration.Builder> withAdditionalConfiguration(Map<String, String> encryptionContext, MultipartConfiguration multipartConfiguration) {
        return builder ->
                builder.putExecutionAttribute(S3EncryptionClient.ENCRYPTION_CONTEXT, encryptionContext)
                        .putExecutionAttribute(S3EncryptionClient.CONFIGURATION, multipartConfiguration);
    }

    // Helper function to determine last upload part during multipart uploads
    public static Consumer<AwsRequestOverrideConfiguration.Builder> isLastPart(Boolean isLastPart) {
        return builder ->
                builder.putExecutionAttribute(S3EncryptionClient.IS_LAST_PART, isLastPart);
    }

    @Override
    public PutObjectResponse putObject(PutObjectRequest putObjectRequest, RequestBody requestBody)
            throws AwsServiceException, SdkClientException {

        if (_enableMultipartPutObject) {
            try {
                // TODO: Confirm best way to wrap CompleteMultipartUploadResponse with PutObjectResponse
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

        CompletableFuture<PutObjectResponse> futurePut = pipeline.putObject(putObjectRequest, AsyncRequestBody.fromInputStream(requestBody.contentStreamProvider().newStream(), requestBody.optionalContentLength().orElse(-1L), Executors.newSingleThreadExecutor()));
        return futurePut.join();
    }

    @Override
    public <T> T getObject(GetObjectRequest getObjectRequest,
                           ResponseTransformer<GetObjectResponse, T> responseTransformer)
            throws AwsServiceException, SdkClientException {

        GetEncryptedObjectPipeline pipeline = GetEncryptedObjectPipeline.builder()
                .s3AsyncClient(_wrappedAsyncClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .enableLegacyUnauthenticatedModes(_enableLegacyUnauthenticatedModes)
                .enableDelayedAuthentication(_enableDelayedAuthenticationMode)
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

        AwsRequestOverrideConfiguration overrideConfig = request.overrideConfiguration().get();
        // If MultipartConfiguration is null, Initialize MultipartConfiguration
        MultipartConfiguration multipartConfiguration = overrideConfig
                .executionAttributes()
                .getOptionalAttribute(S3EncryptionClient.CONFIGURATION)
                .orElse(MultipartConfiguration.builder().build());

        ExecutorService es = multipartConfiguration.executorService();
        final boolean defaultExecutorService = es == null;
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
            if (defaultExecutorService) {
                // shut down the locally created thread pool
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
        return t;
    }

    @Override
    public DeleteObjectResponse deleteObject(DeleteObjectRequest deleteObjectRequest) throws AwsServiceException,
            SdkClientException {
        // Delete the object
        DeleteObjectResponse deleteObjectResponse = _wrappedAsyncClient.deleteObject(deleteObjectRequest).join();
        // If Instruction file exists, delete the instruction file as well.
        String instructionObjectKey = deleteObjectRequest.key() + INSTRUCTION_FILE_SUFFIX;
        _wrappedAsyncClient.deleteObject(builder -> builder
                .bucket(deleteObjectRequest.bucket())
                .key(instructionObjectKey)).join();
        return deleteObjectResponse;
    }

    @Override
    public DeleteObjectsResponse deleteObjects(DeleteObjectsRequest deleteObjectsRequest) throws AwsServiceException,
            SdkClientException {
        // Delete the objects
        DeleteObjectsResponse deleteObjectsResponse = _wrappedAsyncClient.deleteObjects(deleteObjectsRequest).join();
        // If Instruction files exists, delete the instruction files as well.
        List<ObjectIdentifier> deleteObjects = instructionFileKeysToDelete(deleteObjectsRequest);
        _wrappedAsyncClient.deleteObjects(DeleteObjectsRequest.builder()
                .bucket(deleteObjectsRequest.bucket())
                .delete(builder -> builder.objects(deleteObjects))
                .build()).join();
        return deleteObjectsResponse;
    }

    @Override
    public CreateMultipartUploadResponse createMultipartUpload(CreateMultipartUploadRequest request) {
        return _multipartPipeline.createMultipartUpload(request);
    }

    /**
     * <p>
     * <b>NOTE:</b> Because the encryption process requires context from block
     * N-1 in order to encrypt block N, parts uploaded with the
     * S3EncryptionClient (as opposed to the normal S3Client) must
     * be uploaded serially, and in order. Otherwise, the previous encryption
     * context isn't available to use when encrypting the current part.
     */
    @Override
    public UploadPartResponse uploadPart(UploadPartRequest request, RequestBody requestBody)
            throws AwsServiceException, SdkClientException {
        AwsRequestOverrideConfiguration overrideConfiguration = request.overrideConfiguration().orElse(null);
        boolean isLastPart = false;
        if (!(overrideConfiguration == null)) {
            isLastPart = overrideConfiguration.executionAttributes().getOptionalAttribute(IS_LAST_PART).orElse(false);
        }
        return _multipartPipeline.uploadPart(request, requestBody, isLastPart);
    }

    @Override
    public CompleteMultipartUploadResponse completeMultipartUpload(CompleteMultipartUploadRequest request)
            throws AwsServiceException, SdkClientException {
        return _multipartPipeline.completeMultipartUpload(request);
    }

    @Override
    public AbortMultipartUploadResponse abortMultipartUpload(AbortMultipartUploadRequest request)
            throws AwsServiceException, SdkClientException {
        return _multipartPipeline.abortMultipartUpload(request);
    }

    @Override
    public void close() {
        _wrappedClient.close();
        _wrappedAsyncClient.close();
    }

    public static class Builder {
        // The non-encrypted APIs will use a default client.
        private S3Client _wrappedClient = S3Client.create();
        private S3AsyncClient _wrappedAsyncClient = S3AsyncClient.create();

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

        private Builder() {
        }

        /**
         * Sets the wrappedClient to be used for non-cryptographic operations.
         */
        /*
         * Note that this does NOT create a defensive clone of S3AsyncClient. Any modifications made to the wrapped
         * S3AsyncClient will be reflected in this Builder.
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

        public Builder cryptoMaterialsManager(CryptographicMaterialsManager cryptoMaterialsManager) {
            this._cryptoMaterialsManager = cryptoMaterialsManager;
            checkKeyOptions();

            return this;
        }

        public Builder keyring(Keyring keyring) {
            this._keyring = keyring;
            checkKeyOptions();

            return this;
        }

        public Builder aesKey(SecretKey aesKey) {
            this._aesKey = aesKey;
            checkKeyOptions();

            return this;
        }

        public Builder rsaKeyPair(KeyPair rsaKeyPair) {
            this._rsaKeyPair = new PartialRsaKeyPair(rsaKeyPair);
            checkKeyOptions();

            return this;
        }

        public Builder rsaKeyPair(PartialRsaKeyPair partialRsaKeyPair) {
            this._rsaKeyPair = partialRsaKeyPair;
            checkKeyOptions();

            return this;
        }

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

        public Builder enableLegacyWrappingAlgorithms(boolean shouldEnableLegacyWrappingAlgorithms) {
            this._enableLegacyWrappingAlgorithms = shouldEnableLegacyWrappingAlgorithms;
            return this;
        }

        public Builder enableLegacyUnauthenticatedModes(boolean shouldEnableLegacyUnauthenticatedModes) {
            this._enableLegacyUnauthenticatedModes = shouldEnableLegacyUnauthenticatedModes;
            return this;
        }

        public Builder enableDelayedAuthenticationMode(boolean shouldEnableDelayedAuthenticationMode) {
            this._enableDelayedAuthenticationMode = shouldEnableDelayedAuthenticationMode;
            return this;
        }

        public Builder enableMultipartPutObject(boolean _enableMultipartPutObject) {
            this._enableMultipartPutObject = _enableMultipartPutObject;
            return this;
        }

        public Builder cryptoProvider(Provider cryptoProvider) {
            this._cryptoProvider = cryptoProvider;
            return this;
        }

        public Builder secureRandom(SecureRandom secureRandom) {
            if (secureRandom == null) {
                throw new S3EncryptionClientException("SecureRandom provided to S3EncryptionClient cannot be null");
            }
            _secureRandom = secureRandom;
            return this;
        }

        public S3EncryptionClient build() {
            if (!onlyOneNonNull(_cryptoMaterialsManager, _keyring, _aesKey, _rsaKeyPair, _kmsKeyId)) {
                throw new S3EncryptionClientException("Exactly one must be set of: crypto materials manager, keyring, AES key, RSA key pair, KMS key id");
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
