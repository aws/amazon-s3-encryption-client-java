package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.utils.BinaryUtils;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.S3EncryptionClientSecurityException;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.LinkedList;
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
    private final LinkedList<ByteBuffer> buffers = new LinkedList<>();

    BufferedCipherSubscriber(Subscriber<? super ByteBuffer> wrappedSubscriber, Cipher cipher, Long contentLength) {
        this.wrappedSubscriber = wrappedSubscriber;
        this.cipher = cipher;
        if (contentLength == null || contentLength > BUFFERED_MAX_CONTENT_LENGTH_BYTES) {
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
        System.out.println("onNext w BB remaining" + byteBuffer.remaining());
        System.out.println("onNext w BB cap" + byteBuffer.capacity());
        int amountToReadFromByteBuffer = getAmountToReadFromByteBuffer(byteBuffer);
        System.out.println("amt to read from BB: " + amountToReadFromByteBuffer);

        if (amountToReadFromByteBuffer > 0) {
            byte[] buf = BinaryUtils.copyBytesFrom(byteBuffer, amountToReadFromByteBuffer);
            System.out.println("cipher update");
            outputBuffer = cipher.update(buf, 0, amountToReadFromByteBuffer);

            if (outputBuffer == null && amountToReadFromByteBuffer < cipher.getBlockSize()) {
                // The underlying data is too short to fill in the block cipher
                // This is true at the end of the file, so complete to get the final
                // bytes
                System.out.println("right to complete");
                this.onComplete();
            }

            // Enqueue the buffer until all data is read
            System.out.println("enqueue output buffer");
            buffers.add(ByteBuffer.wrap(outputBuffer));

            // Sometimes, onComplete won't be called, so we check if all
            // data is read to avoid hanging indefinitely
            System.out.println("content read: " + contentRead.get());
            System.out.println("content length: " + contentLength);
            if (contentRead.get() == contentLength) {
                System.out.println("competing from onNext");
                this.onComplete();
            }

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
        System.out.println("onComplete");
        if (doneFinal.get()) {
            // doFinal has already been called, bail out
            return;
        }
        try {
            System.out.println("doFinal");
            outputBuffer = cipher.doFinal();
            doneFinal.set(true);
            System.out.println("doneFinal");
            // Once doFinal is called, then we can release the plaintext
            if (contentRead.get() == contentLength) {
                System.out.println("start release");
                while (!buffers.isEmpty()) {
                    System.out.println("releasing...");
                    wrappedSubscriber.onNext(buffers.remove());
                }
            }
            System.out.println("now final bytes...");
            // Send the final bytes to the wrapped subscriber
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
        } catch (final GeneralSecurityException exception) {
            System.out.println("ope...");
            exception.printStackTrace();
            // Forward error, else the wrapped subscriber waits indefinitely
            wrappedSubscriber.onError(exception);
            throw new S3EncryptionClientSecurityException(exception.getMessage(), exception);
        }
        System.out.println("completing!");
        wrappedSubscriber.onComplete();
        System.out.println("donezo");
    }
}
