package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.encryption.s3.materials.CryptographicMaterials;

import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * An AsyncRequestBody which encrypts and decrypts data as it passes through
 * using a configured Cipher instance.
 */
public class CipherAsyncRequestBody implements AsyncRequestBody {

    private final AsyncRequestBody wrappedAsyncRequestBody;
    private final Long ciphertextLength;
    private final CryptographicMaterials materials;
    private final byte[] iv;

    public CipherAsyncRequestBody(final AsyncRequestBody wrappedAsyncRequestBody, final Long ciphertextLength, final CryptographicMaterials materials, final byte[] iv) {
        this.wrappedAsyncRequestBody = wrappedAsyncRequestBody;
        this.ciphertextLength = ciphertextLength;
        this.materials = materials;
        this.iv = iv;
    }

    @Override
    public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
        wrappedAsyncRequestBody.subscribe(new CipherSubscriber(subscriber, contentLength().orElse(-1L), materials, iv));
    }

    @Override
    public Optional<Long> contentLength() {
        return Optional.of(ciphertextLength);
    }
}
