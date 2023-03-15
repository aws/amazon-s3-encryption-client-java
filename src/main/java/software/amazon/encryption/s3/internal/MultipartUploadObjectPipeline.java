package software.amazon.encryption.s3.internal;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.AbortMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.AbortMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.EncryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterialsRequest;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;

public class MultipartUploadObjectPipeline {
    final private S3AsyncClient _s3AsyncClient;
    final private CryptographicMaterialsManager _cryptoMaterialsManager;
    final private MultipartContentEncryptionStrategy _contentEncryptionStrategy;
    final private ContentMetadataEncodingStrategy _contentMetadataEncodingStrategy;
    /**
     * Map of data about in progress encrypted multipart uploads.
     */
    private final Map<String, MultipartUploadContext> _multipartUploadContexts;

    private MultipartUploadObjectPipeline(Builder builder) {
        this._s3AsyncClient = builder._s3AsyncClient;
        this._cryptoMaterialsManager = builder._cryptoMaterialsManager;
        this._contentEncryptionStrategy = builder._contentEncryptionStrategy;
        this._contentMetadataEncodingStrategy = builder._contentMetadataEncodingStrategy;
        this._multipartUploadContexts = builder._multipartUploadContexts;
    }

    public static Builder builder() {
        return new Builder();
    }

    public CreateMultipartUploadResponse createMultipartUpload(CreateMultipartUploadRequest request) {
        EncryptionMaterialsRequest.Builder requestBuilder = EncryptionMaterialsRequest.builder()
                .s3Request(request);

        EncryptionMaterials materials = _cryptoMaterialsManager.getEncryptionMaterials(requestBuilder.build());
        EncryptedContent encryptedContent = _contentEncryptionStrategy.initMultipartEncryption(materials);

        Map<String, String> metadata = new HashMap<>(request.metadata());
        metadata = _contentMetadataEncodingStrategy.encodeMetadata(materials, encryptedContent.getNonce(), metadata);
        request = request.toBuilder().metadata(metadata).build();

        CreateMultipartUploadResponse response = _s3AsyncClient.createMultipartUpload(request).join();

        MultipartUploadContext multipartUploadContext = new MultipartUploadContext(encryptedContent.getCipher());
        _multipartUploadContexts.put(response.uploadId(), multipartUploadContext);

        return response;
    }

    public UploadPartResponse uploadPart(UploadPartRequest request, RequestBody requestBody, boolean isLastPart)
            throws AwsServiceException, SdkClientException {
        final AlgorithmSuite algorithmSuite = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
        final int blockSize = algorithmSuite.cipherBlockSizeBytes();
        // Validate the partSize / contentLength in the request and requestBody
        // There is similar logic in PutEncryptedObjectPipeline,
        // but this uses non-async requestBody, so the code is not shared
        final long partContentLength;
        if (request.contentLength() != null) {
            if (requestBody.optionalContentLength().isPresent() && !request.contentLength().equals(requestBody.optionalContentLength().get())) {
                // if the contentLength values do not match, throw an exception, since we don't know which is correct
                throw new S3EncryptionClientException("The contentLength provided in the request object MUST match the " +
                        "contentLength in the request body");
            } else if (!requestBody.optionalContentLength().isPresent()) {
                // no contentLength in request body, use the one in request
                partContentLength = request.contentLength();
            } else {
                // only remaining case is when the values match, so either works here
                partContentLength = request.contentLength();
            }
        } else {
            partContentLength = requestBody.optionalContentLength().orElse(-1L);
        }

        final int cipherTagLength = isLastPart ? algorithmSuite.cipherTagLengthBytes() : 0;
        final long ciphertextLength = partContentLength + cipherTagLength;
        final boolean partSizeMultipleOfCipherBlockSize = 0 == (partContentLength % blockSize);

        if (!isLastPart && !partSizeMultipleOfCipherBlockSize) {
            throw new S3EncryptionClientException("Invalid part size: part sizes for encrypted multipart uploads must " +
                    "be multiples of the cipher block size (" + blockSize + ") with the exception of the last part.");
        }

        final String uploadId = request.uploadId();
        final MultipartUploadContext uploadContext = _multipartUploadContexts.get(uploadId);
        if (uploadContext == null) {
            throw new S3EncryptionClientException("No client-side information available on upload ID " + uploadId);
        }
        final UploadPartResponse response;
        // Checks the parts are uploaded in series
        uploadContext.beginPartUpload(request.partNumber());
        Cipher cipher = uploadContext.getCipher();
        try {
            final AsyncRequestBody cipherAsyncRequestBody = new CipherAsyncRequestBody(cipher, AsyncRequestBody.fromInputStream(requestBody.contentStreamProvider().newStream(), request.contentLength(), Executors.newSingleThreadExecutor()), ciphertextLength);
            // The last part of the multipart upload will contain an extra
            // 16-byte mac
            if (isLastPart) {
                if (uploadContext.hasFinalPartBeenSeen()) {
                    throw new S3EncryptionClientException("This part was specified as the last part in a multipart " +
                            "upload, but a previous part was already marked as the last part. Only the last part of the " +
                            "upload should be marked as the last part.");
                }
            }
            response =  _s3AsyncClient.uploadPart(request, cipherAsyncRequestBody).join();
        } finally {
            uploadContext.endPartUpload();
        }
        if (isLastPart) {
            uploadContext.setHasFinalPartBeenSeen(true);
        }
        return response;
    }

    public CompleteMultipartUploadResponse completeMultipartUpload(CompleteMultipartUploadRequest request)
            throws AwsServiceException, SdkClientException {
        String uploadId = request.uploadId();
        final MultipartUploadContext uploadContext = _multipartUploadContexts.get(uploadId);

        if (uploadContext != null && !uploadContext.hasFinalPartBeenSeen()) {
            throw new S3EncryptionClientException(
                    "Unable to complete an encrypted multipart upload without being told which part was the last.  "
                            + "Without knowing which part was the last, the encrypted data in Amazon S3 is incomplete and corrupt.");
        }
        CompleteMultipartUploadResponse response = _s3AsyncClient.completeMultipartUpload(request).join();

        _multipartUploadContexts.remove(uploadId);
        return response;
    }

    public AbortMultipartUploadResponse abortMultipartUpload(AbortMultipartUploadRequest request) {
        _multipartUploadContexts.remove(request.uploadId());
        return _s3AsyncClient.abortMultipartUpload(request).join();
    }

    public void putLocalObject(RequestBody requestBody, String uploadId, OutputStream os) throws IOException {
        final MultipartUploadContext uploadContext = _multipartUploadContexts.get(uploadId);
        Cipher cipher = uploadContext.getCipher();
        final InputStream cipherInputStream = new AuthenticatedCipherInputStream(requestBody.contentStreamProvider().newStream(), cipher);

        try {
            IoUtils.copy(cipherInputStream, os);
            // so it won't crap out with a false negative at the end; (Not
            // really relevant here)
            uploadContext.setHasFinalPartBeenSeen(true);
        } finally {
            // This will create last part of MultiFileOutputStream upon close
            IoUtils.closeQuietly(os, null);
        }
    }

    public static class Builder {
        private final Map<String, MultipartUploadContext> _multipartUploadContexts =
                Collections.synchronizedMap(new HashMap<>());
        private final ContentMetadataEncodingStrategy _contentMetadataEncodingStrategy = ContentMetadataStrategy.OBJECT_METADATA;
        private S3AsyncClient _s3AsyncClient;
        private CryptographicMaterialsManager _cryptoMaterialsManager;
        private SecureRandom _secureRandom;
        // To Create Cipher which is used in during uploadPart requests.
        private MultipartContentEncryptionStrategy _contentEncryptionStrategy;

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

        public Builder secureRandom(SecureRandom secureRandom) {
            this._secureRandom = secureRandom;
            return this;
        }

        public MultipartUploadObjectPipeline build() {
            // Default to AesGcm since it is the only active (non-legacy) content encryption strategy
            if (_contentEncryptionStrategy == null) {
                _contentEncryptionStrategy = StreamingAesGcmContentStrategy
                        .builder()
                        .secureRandom(_secureRandom)
                        .build();
            }
            return new MultipartUploadObjectPipeline(this);
        }
    }
}
