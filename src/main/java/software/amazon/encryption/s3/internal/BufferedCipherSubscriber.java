package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.utils.BinaryUtils;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.S3EncryptionClientSecurityException;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A subscriber which decrypts data by buffering the object's contents
 * so that authentication can be done before any plaintext is released.
 * This prevents "release of unauthenticated plaintext" at the cost of
 * allocating a large buffer.
 */
public class BufferedCipherSubscriber implements Subscriber<ByteBuffer> {

    // 64MiB ought to be enough for most usecases
    private static final long BUFFERED_MAX_CONTENT_LENGTH_MiB = 64;
    private static final long BUFFERED_MAX_CONTENT_LENGTH_BYTES = 1024 * 1024 * BUFFERED_MAX_CONTENT_LENGTH_MiB;

    private final AtomicInteger contentRead = new AtomicInteger(0);
    private final AtomicBoolean doneFinal = new AtomicBoolean(false);
    private final Subscriber<? super ByteBuffer> wrappedSubscriber;
    private final Cipher cipher;
    private final int contentLength;

    private byte[] outputBuffer;
    private final Queue<ByteBuffer> buffers = new ConcurrentLinkedQueue<>();

    BufferedCipherSubscriber(Subscriber<? super ByteBuffer> wrappedSubscriber, Cipher cipher, Long contentLength) {
        this.wrappedSubscriber = wrappedSubscriber;
        this.cipher = cipher;
        if (contentLength == null) {
            throw new S3EncryptionClientException("contentLength cannot be null in buffered mode. To enable unbounded " +
                    "streaming, reconfigure the S3 Encryption Client with Delayed Authentication mode enabled.");
        }
        if (contentLength > BUFFERED_MAX_CONTENT_LENGTH_BYTES) {
            throw new S3EncryptionClientException(String.format("The object you are attempting to decrypt exceeds the maximum content " +
                    "length allowed in default mode. Please enable Delayed Authentication mode to decrypt objects larger" +
                    "than %d", BUFFERED_MAX_CONTENT_LENGTH_MiB));
        }
        this.contentLength = Math.toIntExact(contentLength);
    }

    @Override
    public void onSubscribe(Subscription s) {
        wrappedSubscriber.onSubscribe(s);
    }

    @Override
    public void onNext(ByteBuffer byteBuffer) {
        int amountToReadFromByteBuffer = getAmountToReadFromByteBuffer(byteBuffer);

        if (amountToReadFromByteBuffer > 0) {
            byte[] buf = BinaryUtils.copyBytesFrom(byteBuffer, amountToReadFromByteBuffer);
            try {
                outputBuffer = cipher.update(buf, 0, amountToReadFromByteBuffer);
            } catch (final IllegalStateException exception) {
                // TODO: Implement retries. For now, forward and rethrow.
                this.onError(exception);
                throw exception;
            }

            if (outputBuffer == null && amountToReadFromByteBuffer < cipher.getBlockSize()) {
                // The underlying data is too short to fill in the block cipher
                // This is true at the end of the file, so complete to get the final
                // bytes
                this.onComplete();
            }

            // Enqueue the buffer until all data is read
            buffers.add(ByteBuffer.wrap(outputBuffer));

            // Sometimes, onComplete won't be called, so we check if all
            // data is read to avoid hanging indefinitely
            if (contentRead.get() == contentLength) {
                this.onComplete();
            }
            // This avoids the subscriber waiting indefinitely for more data
            // without actually releasing any plaintext before it can be authenticated
            wrappedSubscriber.onNext(ByteBuffer.allocate(0));
        }

    }

    private int getAmountToReadFromByteBuffer(ByteBuffer byteBuffer) {

        long amountReadSoFar = contentRead.getAndAdd(byteBuffer.remaining());
        long amountRemaining = Math.max(0, contentLength - amountReadSoFar);

        if (amountRemaining > byteBuffer.remaining()) {
            return byteBuffer.remaining();
        } else {
            return Math.toIntExact(amountRemaining);
        }
    }

    @Override
    public void onError(Throwable t) {
        wrappedSubscriber.onError(t);
    }

    @Override
    public void onComplete() {
        if (doneFinal.get()) {
            // doFinal has already been called, bail out
            return;
        }
        try {
            outputBuffer = cipher.doFinal();
            doneFinal.set(true);
            // Once doFinal is called, then we can release the plaintext
            if (contentRead.get() == contentLength) {
                while (!buffers.isEmpty()) {
                    wrappedSubscriber.onNext(buffers.remove());
                }
            }
            // Send the final bytes to the wrapped subscriber
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
        } catch (final GeneralSecurityException exception) {
            // Forward error, else the wrapped subscriber waits indefinitely
            wrappedSubscriber.onError(exception);
            throw new S3EncryptionClientSecurityException(exception.getMessage(), exception);
        }
        wrappedSubscriber.onComplete();
    }
}
