package software.amazon.encryption.s3;

import software.amazon.awssdk.core.exception.SdkClientException;

public class S3EncryptionClientException extends SdkClientException {

    public S3EncryptionClientException(String message) {
        super(SdkClientException.builder()
                .message(message));
    }

    public S3EncryptionClientException(String message, Throwable cause) {
        super(SdkClientException.builder()
                .message(message)
                .cause(cause));
    }
}
