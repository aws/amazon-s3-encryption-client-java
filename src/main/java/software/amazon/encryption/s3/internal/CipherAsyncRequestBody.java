package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.utils.BinaryUtils;
import software.amazon.encryption.s3.S3EncryptionClientSecurityException;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A Publisher which encrypts and decrypts data as it passes through
 * using a configured Cipher instance.
 */
public class CipherAsyncRequestBody implements AsyncRequestBody {

    private final AsyncRequestBody wrapped;
    private final Cipher cipher;
    private final Long ciphertextLength;

    public CipherAsyncRequestBody(final Cipher cipher, final AsyncRequestBody wrapped, final Long ciphertextLength){
        this.cipher = cipher;
        this.wrapped = wrapped;
        this.ciphertextLength = ciphertextLength;
    }

    private static final class CipherSubscriber implements Subscriber<ByteBuffer> {
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
                System.out.println("amt to read: " + amountToReadFromByteBuffer);
                System.out.println("in: " + new String(buf));
                System.out.println("it is " + buf.length + " bytesworth-in");
                outputBuffer = cipher.update(buf, 0, amountToReadFromByteBuffer);
                System.out.println("out: " + new String(outputBuffer));
                System.out.println("it is: " + outputBuffer.length + " bytesworth-out");
                wrapped.onNext(ByteBuffer.wrap(outputBuffer));
            } else {
                // Do nothing?
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
                System.out.println("also out: " + new String(outputBuffer));
                System.out.println("it is: " + outputBuffer.length + " bytesworth-out");
                wrapped.onNext(ByteBuffer.wrap(outputBuffer));
            } catch (final GeneralSecurityException exception) {
                throw new S3EncryptionClientSecurityException(exception.getMessage(), exception);
            }
            wrapped.onComplete();
        }
    }

    @Override
    public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
        wrapped.subscribe(new CipherSubscriber(subscriber, cipher, contentLength().orElse(-1L)));
    }

    @Override
    public Optional<Long> contentLength() {
        return Optional.of(ciphertextLength);
    }
}
