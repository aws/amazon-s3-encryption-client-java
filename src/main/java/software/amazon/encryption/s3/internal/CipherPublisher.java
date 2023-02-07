package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import software.amazon.awssdk.core.async.SdkPublisher;
import software.amazon.encryption.s3.legacy.internal.RangedGetUtils;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;

/**
 * A Publisher which encrypts and decrypts data as it passes through
 * using a configured Cipher instance.
 */
public class CipherPublisher implements SdkPublisher<ByteBuffer> {

    private final SdkPublisher<ByteBuffer> wrappedPublisher;
    private final Cipher cipher;
    private final Long contentLength;
    private final long[] range;
    private final String contentRange;
    private final int cipherTagLengthBits;

    public CipherPublisher(final Cipher cipher, final SdkPublisher<ByteBuffer> wrappedPublisher, final Long contentLength, long[] range, String contentRange, int cipherTagLengthBits) {
        this.wrappedPublisher = wrappedPublisher;
        this.cipher = cipher;
        this.contentLength = contentLength;
        this.range = range;
        this.contentRange = contentRange;
        this.cipherTagLengthBits = cipherTagLengthBits;
    }

    @Override
    public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
        // Wrap the (customer) subscriber in a CipherSubscriber, then subscribe it
        // to the wrapped (ciphertext) publisher
        Subscriber wrappedSubscriber = RangedGetUtils.adjustToDesiredRange(subscriber, range, contentRange, cipherTagLengthBits);
        wrappedPublisher.subscribe(new CipherSubscriber(wrappedSubscriber, cipher, contentLength));
    }
}
