package software.amazon.encryption.s3;

public class SubscriberResetException extends S3EncryptionClientException {

    public SubscriberResetException(String message) {
        super(message);
    }

    public SubscriberResetException(String message, Throwable cause) {
        super(message, cause);
    }
}
