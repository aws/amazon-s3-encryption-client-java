package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.utils.BinaryUtils;
import software.amazon.encryption.s3.S3EncryptionClientSecurityException;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class CipherSubscriber implements Subscriber<ByteBuffer> {
    private final AtomicLong contentRead = new AtomicLong(0);
    // true means doFinal was called
    private final AtomicBoolean finalized = new AtomicBoolean(false);
    private final Subscriber<? super ByteBuffer> wrappedSubscriber;
    private final Cipher cipher;
    private final Long contentLength;
    private Subscription subscription;

    private byte[] outputBuffer;

    CipherSubscriber(Subscriber<? super ByteBuffer> wrappedSubscriber, Cipher cipher, Long contentLength) {
        this.wrappedSubscriber = wrappedSubscriber;
        this.cipher = cipher;
        this.contentLength = contentLength;
    }

    @Override
    public void onSubscribe(Subscription s) {
        if (finalized.get()) {
            System.out.println("cipher already finalized!");
            System.out.println("canceling the subscription");
            s.cancel();
            //wrappedSubscriber.onComplete();
        }
        System.out.println("subscribing..");
        this.subscription = s;
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
                // Either the cipher was never init'd or we are attempting to reinit
                // with the same key/IV after calling doFinal. The latter is true when
                // there is a connection reset.
                // This is why the aux cipher exists.
                // So we have a couple options:
                // - fail closed, forcing a retry of S3EC::putObject which would generate a new
                //   data key + IV. The problem with this is that customers MUST be able to configure
                //   retry behavior. Currently, this is done by configuring the RetryPolicy ClientOverride
                //   in the wrapped client. If it were possible for the S3 EC to inspect the RetryPolicy,
                //   it might be possible to make the S3 EC's putObject (which includes IV generation etc)
                //   behave the same way. However, inspection is not possible and even if it was, the
                //   retry behavior is specific to HTTP. This is also a regression in S3 EC because V2
                //   provides a solution to this. (See also customer ticket complaining about lack of
                //   mark/reset in ESDK.)
                // - reset GCM cipher using the same data key + IV is NOT FEASIBLE because of security
                //   reasons...probably (unless the data changes, it's actually fine)
                // - use an aux cipher in CTR mode to replay the encryption without resetting the
                //   GCM cipher
                // - reset GCM cipher with new data key/IV within the Subscriber. This is a large refactor.
                //   It would address key/IV reuse because the IV would be set only once the operation is
                //   completed. This also only works if the subscriber starts over from the beginning.
                //
                // The first option is a poor customer experience. The second and third are arguably different
                // implementations of the same idea. The salient difference is that the aux cipher would do a
                // better job when the "reset" is not at the beginning of the stream. If the reset always goes
                // back to the beginning, we might as well just reset the cipher and start over with the same IV.

//                System.out.println("illegalstateexception, cipher probably was reinitialized..");
//                System.out.println("contentRead is " + contentRead);
//                System.out.println("contentLength is " + contentLength);
//                System.out.println("amtToReadFromBuffer is " + amountToReadFromByteBuffer);
//                System.out.println("buflen is " + buf.length);
                exception.printStackTrace();
//                subscription.cancel();
//                wrappedSubscriber.onError(exception);
                //throw new SubscriberResetException(exception.getMessage(), exception);

                // Alternatively, it's possible that this is just a race condition, not a retry?
                // The boolean guard isn't working; this implies race condition.
                // Let's try doing nothing.
                System.out.println("returning from onNext without doing anything..");
                return;
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
            System.out.println("doing nothing!");
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
        // TODO: it's possible this isn't handled correctly
        System.out.println("onError called! forwarding..");
        t.printStackTrace();
        wrappedSubscriber.onError(t);
    }

    @Override
    public void onComplete() {
        try {
            outputBuffer = cipher.doFinal();
            finalized.compareAndSet(false, true);
            System.out.println("doFinal called successfully.");
            System.out.println("complete contentRead is " + contentRead);
            System.out.println("complete contentLength is " + contentLength);
            // Send the final bytes to the wrapped subscriber
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
        } catch (final GeneralSecurityException exception) {
            throw new S3EncryptionClientSecurityException(exception.getMessage(), exception);
        }
        wrappedSubscriber.onComplete();
        System.out.println("complete!");
    }
}