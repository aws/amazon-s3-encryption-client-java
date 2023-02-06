package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.utils.BinaryUtils;
import software.amazon.encryption.s3.S3EncryptionClientSecurityException;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.concurrent.atomic.AtomicLong;

public class CipherSubscriber implements Subscriber<ByteBuffer> {
    private final AtomicLong contentRead = new AtomicLong(0);
    private final Subscriber<? super ByteBuffer> wrappedSubscriber;
    private final Cipher cipher;
    private final Long contentLength;

    private byte[] outputBuffer;

    CipherSubscriber(Subscriber<? super ByteBuffer> wrappedSubscriber, Cipher cipher, Long contentLength) {
        this.wrappedSubscriber = wrappedSubscriber;
        this.cipher = cipher;
        this.contentLength = contentLength;
        System.out.println(" ctor");
    }

    @Override
    public void onSubscribe(Subscription s) {
        System.out.println(" onSub");
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
                System.out.println("caught illegal state exception while updating cipher..");
                // The cipher is in an illegal state, which probably means
                // we are trying to reinitialize with the same key/IV.
            }
            if (outputBuffer == null && amountToReadFromByteBuffer < cipher.getBlockSize()) {
                // The underlying data is too short to fill in the block cipher
                // This is true at the end of the file, so complete to get the final
                // bytes
                this.onComplete();
            }
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
        } else {
            // Do nothing
            wrappedSubscriber.onNext(byteBuffer);
        }
    }

    private int getAmountToReadFromByteBuffer(ByteBuffer byteBuffer) {
        // If content length is null, we should include everything in the cipher because the stream is essentially
        // unbounded.
        if (contentLength == null) {
            return byteBuffer.remaining();
        }

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
        System.out.println(" onError");
        wrappedSubscriber.onError(t);
    }

    @Override
    public void onComplete() {
        System.out.println(" onComplete");
        try {
            outputBuffer = cipher.doFinal();
            // Send the final bytes to the wrapped subscriber
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
        } catch (final GeneralSecurityException exception) {
            throw new S3EncryptionClientSecurityException(exception.getMessage(), exception);
        }
        wrappedSubscriber.onComplete();
    }
}