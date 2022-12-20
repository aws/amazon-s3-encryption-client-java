package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import software.amazon.awssdk.core.async.SdkPublisher;

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

    public CipherPublisher(final Cipher cipher, final SdkPublisher<ByteBuffer> wrappedPublisher, final Long contentLength){
        this.wrappedPublisher = wrappedPublisher;
        this.cipher = cipher;
        this.contentLength = contentLength;
    }

    @Override
    public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
        // Wrap the (customer) subscriber in a CipherSubscriber, then subscribe it
        // to the wrapped (ciphertext) publisher
        wrappedPublisher.subscribe(new CipherSubscriber(subscriber, cipher, contentLength));
    }
}
