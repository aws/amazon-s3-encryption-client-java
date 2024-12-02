package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.encryption.s3.S3EncryptionClientException;

/**
 * Provides configuration options for instruction file behaviors.
 */
public class InstructionFileConfig {

    final private InstructionFileClientType _clientType;
    final private S3AsyncClient _s3AsyncClient;
    final private S3Client _s3Client;
    final private boolean _enableInstructionFilePut;

    private InstructionFileConfig(final Builder builder) {
        _clientType = builder._clientType;
        _s3Client = builder._s3Client;
        _s3AsyncClient = builder._s3AsyncClient;
        _enableInstructionFilePut = builder._enableInstructionFilePut;
    }

    public static Builder builder() {
        return new Builder();
    }

    public enum InstructionFileClientType {
        DISABLED,
        SYNCHRONOUS,
        ASYNC
    }

    boolean isInstructionFilePutEnabled() {
        return _enableInstructionFilePut;
    }

    PutObjectResponse putInstructionFile(PutObjectRequest request, String instructionFileContent) {
        // This shouldn't happen in practice because the metadata strategy will evaluate
        // if instruction file Puts are enabled before calling this method; check again anyway for robustness
        if (!_enableInstructionFilePut) {
            throw new S3EncryptionClientException("Enable Instruction File Put must be set to true in order to call PutObject with an instruction file!");
        }
        switch (_clientType) {
            case SYNCHRONOUS:
                return _s3Client.putObject(request, RequestBody.fromString(instructionFileContent));
            case ASYNC:
                return _s3AsyncClient.putObject(request, AsyncRequestBody.fromString(instructionFileContent)).join();
            case DISABLED:
                // this should never happen because we check enablePut first
                throw new S3EncryptionClientException("Instruction File has been disabled!");
            default:
                // this should never happen
                throw new S3EncryptionClientException("Unknown Instruction File Type");
        }
    }

    ResponseInputStream<GetObjectResponse> getInstructionFile(GetObjectRequest request) {
        switch (_clientType) {
            case SYNCHRONOUS:
                return _s3Client.getObject(request);
            case ASYNC:
                return _s3AsyncClient.getObject(request, AsyncResponseTransformer.toBlockingInputStream()).join();
            case DISABLED:
                throw new S3EncryptionClientException("Instruction File has been disabled!");
            default:
                // this should never happen
                throw new S3EncryptionClientException("Unknown Instruction File Type");
        }
    }

    /**
     * Closes the S3Client or S3AsyncClient used for instruction files.
     */
    public void closeClient() {
        if (_s3AsyncClient != null) {
            _s3AsyncClient.close();
        }
        if (_s3Client != null) {
            _s3Client.close();
        }
    }

    public static class Builder {
        private InstructionFileClientType _clientType;
        private boolean _disableInstructionFile;
        private S3AsyncClient _s3AsyncClient;
        private S3Client _s3Client;
        private boolean _enableInstructionFilePut;

        /**
         * When set to true, the S3 Encryption Client will not attempt to get instruction files.
         * @param disableInstructionFile
         * @return
         */
        public Builder disableInstructionFile(boolean disableInstructionFile) {
            _disableInstructionFile = disableInstructionFile;
            return this;
        }

        public Builder enableInstructionFilePutObject(boolean enableInstructionFilePutObject) {
            _enableInstructionFilePut = enableInstructionFilePutObject;
            return this;
        }

        /**
         * Sets the S3 client to use to retrieve instruction files.
         * @param instructionFileClient
         * @return
         */
        public Builder instructionFileClient(S3Client instructionFileClient) {
            _s3Client = instructionFileClient;
            return this;
        }

        /**
         * Sets the S3 Async client to use to retrieve instruction files.
         * @param instructionFileAsyncClient
         * @return
         */
        public Builder instructionFileAsyncClient(S3AsyncClient instructionFileAsyncClient) {
            _s3AsyncClient = instructionFileAsyncClient;
            return this;
        }

        public InstructionFileConfig build() {
            if ((_s3AsyncClient != null || _s3Client != null) && _disableInstructionFile) {
                throw new S3EncryptionClientException("Instruction Files have been disabled but a client has been passed!");
            }
            if (_disableInstructionFile) {
                // We know both clients are null, so carry on.
                this._clientType = InstructionFileClientType.DISABLED;
                if (_enableInstructionFilePut) {
                    throw new S3EncryptionClientException("Instruction Files must be enabled to enable Instruction Files for PutObject.");
                }
                return new InstructionFileConfig(this);
            }
            if (_s3Client != null && _s3AsyncClient != null) {
                throw new S3EncryptionClientException("Only one instruction file client may be set.");
            }
            if (_s3Client != null) {
                _clientType = InstructionFileClientType.SYNCHRONOUS;
            } else if (_s3AsyncClient != null){
                _clientType = InstructionFileClientType.ASYNC;
            } else {
                throw new S3EncryptionClientException(
                    "At least one instruction file client must be set or Instruction Files MUST be disabled."
                );
            }

            return new InstructionFileConfig(this);
        }
    }
}
