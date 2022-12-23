package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import software.amazon.awssdk.core.async.AsyncRequestBody;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * An AsyncRequestBody which encrypts and decrypts data as it passes through
 * using a configured Cipher instance.
 */
public class CipherAsyncRequestBody implements AsyncRequestBody {

    private final AsyncRequestBody wrappedAsyncRequestBody;
    private final Cipher cipher;
    private final Long ciphertextLength;

    public CipherAsyncRequestBody(final Cipher cipher, final AsyncRequestBody wrappedAsyncRequestBody, final Long ciphertextLength){
        this.cipher = cipher;
        this.wrappedAsyncRequestBody = wrappedAsyncRequestBody;
        this.ciphertextLength = ciphertextLength;
    }

    @Override
    public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
        wrappedAsyncRequestBody.subscribe(new CipherSubscriber(subscriber, cipher, contentLength().orElse(-1L)));
    }

    @Override
    public Optional<Long> contentLength() {
        return Optional.of(ciphertextLength);
    }
}
