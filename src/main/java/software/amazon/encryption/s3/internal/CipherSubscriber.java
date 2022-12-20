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
    private final Subscriber<? super ByteBuffer> wrapped;
    private final Cipher cipher;
    private final Long contentLength;

    private byte[] outputBuffer;

    CipherSubscriber(Subscriber<? super ByteBuffer> wrapped, Cipher cipher, Long contentLength) {
        this.wrapped = wrapped;
        this.cipher = cipher;
        this.contentLength = contentLength;
    }

    @Override
    public void onSubscribe(Subscription s) {
        wrapped.onSubscribe(s);
    }

    @Override
    public void onNext(ByteBuffer byteBuffer) {
        int amountToReadFromByteBuffer = getAmountToReadFromByteBuffer(byteBuffer);

        if (amountToReadFromByteBuffer > 0) {
            byte[] buf = BinaryUtils.copyBytesFrom(byteBuffer, amountToReadFromByteBuffer);
            outputBuffer = cipher.update(buf, 0, amountToReadFromByteBuffer);
            wrapped.onNext(ByteBuffer.wrap(outputBuffer));
        } else {
            // Do nothing
            wrapped.onNext(byteBuffer);
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
        wrapped.onError(t);
    }

    @Override
    public void onComplete() {
        try {
            outputBuffer = cipher.doFinal();
            // Send the final bytes to the wrapped subscriber
            wrapped.onNext(ByteBuffer.wrap(outputBuffer));
        } catch (final GeneralSecurityException exception) {
            throw new S3EncryptionClientSecurityException(exception.getMessage(), exception);
        }
        wrapped.onComplete();
    }
}