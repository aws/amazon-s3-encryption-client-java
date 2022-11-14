package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientException;

import javax.crypto.Cipher;

public class MultipartUploadContext {

    private boolean hasFinalPartBeenSeen;
    private final Cipher cipher;

    public MultipartUploadContext(Cipher cipher) {
        this.cipher = cipher;
    }

    public final boolean hasFinalPartBeenSeen() {
        return hasFinalPartBeenSeen;
    }

    public final void setHasFinalPartBeenSeen(boolean hasFinalPartBeenSeen) {
        this.hasFinalPartBeenSeen = hasFinalPartBeenSeen;
    }

    /**
     * Can be used to enforce serial uploads.
     */
    private int partNumber;

    /**
     * True if a multipart upload is currently in progress; false otherwise.
     */
    private volatile boolean partUploadInProgress;

    /**
     * Convenient method to return the content encrypting cipher (which is
     * stateful) for the multipart uploads.
     */
    Cipher getCipher() {
        return cipher;
    }

    /**
     * Can be used to check the next part number must either be the same (if it
     * was an retry) or increment by exactly 1 during a serial part uploads.
     * <p>
     * As a side effect, the {@link #partUploadInProgress} will be set to true
     * upon successful completion of this method. Caller of this method is
     * responsible to call {@link #endPartUpload()} in a finally block once
     * the respective part-upload is completed (either normally or abruptly).
     *
     * @throws S3EncryptionClientException if parallel part upload is detected
     * @see #endPartUpload()
     */
    void beginPartUpload(final int nextPartNumber) {
        if (nextPartNumber < 1)
            throw new IllegalArgumentException("part number must be at least 1");
        if (partUploadInProgress) {
            throw new S3EncryptionClientException(
                    "Parts are required to be uploaded in series");
        }
        synchronized (this) {
            if (nextPartNumber - partNumber <= 1) {
                partNumber = nextPartNumber;
                partUploadInProgress = true;
            } else {
                throw new S3EncryptionClientException(
                        "Parts are required to be uploaded in series (partNumber="
                                + partNumber + ", nextPartNumber="
                                + nextPartNumber + ")");
            }
        }
    }

    /**
     * Used to mark the completion of a part upload before the next. Should be
     * invoked in a finally block, and must be preceded previously by a call to
     * {@link #beginPartUpload(int)}.
     *
     * @see #beginPartUpload(int)
     */
    void endPartUpload() {
        partUploadInProgress = false;
    }
}