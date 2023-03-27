package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.CryptographicMaterials;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * An AsyncRequestBody which encrypts and decrypts data as it passes through
 * using a configured Cipher instance.
 */
public class CipherAsyncRequestBody implements AsyncRequestBody {

    private final AsyncRequestBody wrappedAsyncRequestBody;
    private final Long ciphertextLength;
    private final CryptographicMaterials materials;
    private final byte[] iv;
    private final CountDownLatch subscribedLatch = new CountDownLatch(1);
    private final AtomicBoolean subscribeCalled = new AtomicBoolean(false);

    public CipherAsyncRequestBody(final AsyncRequestBody wrappedAsyncRequestBody, final Long ciphertextLength, final CryptographicMaterials materials, final byte[] iv, final boolean isLastPart) {
        this.wrappedAsyncRequestBody = wrappedAsyncRequestBody;
        this.ciphertextLength = ciphertextLength;
        this.materials = materials;
        this.iv = iv;
    }

    public CipherAsyncRequestBody(final AsyncRequestBody wrappedAsyncRequestBody, final Long ciphertextLength, final CryptographicMaterials materials, final byte[] iv) {
        // When no partType is specified, it's not multipart, so there's one part, which must be the last
        this(wrappedAsyncRequestBody, ciphertextLength, materials, iv, true);
    }

    @Override
    public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
        System.out.println("Subscribe called!");
        if (materials.cipherMode().equals(CipherMode.MULTIPART_ENCRYPT) && subscribeCalled.compareAndSet(false, true)) {
            System.out.println(" ...for the first time");
            subscribedLatch.countDown();
            wrappedAsyncRequestBody.subscribe(new CipherSubscriber(subscriber, contentLength().orElse(-1L), materials, iv));
        } else if (materials.cipherMode().equals(CipherMode.MULTIPART_ENCRYPT)) {
            System.out.println(" ...for NOT the first time!");
            throw new S3EncryptionClientException("Retry is not supported for MPU!");
        } else {
            wrappedAsyncRequestBody.subscribe(new CipherSubscriber(subscriber, contentLength().orElse(-1L), materials, iv));
        }
    }

    @Override
    public Optional<Long> contentLength() {
        return Optional.of(ciphertextLength);
    }
}
