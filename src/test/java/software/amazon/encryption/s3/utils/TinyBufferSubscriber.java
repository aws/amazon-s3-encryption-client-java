package software.amazon.encryption.s3.utils;

import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.utils.BinaryUtils;

import java.nio.ByteBuffer;

/**
 * Subscriber which purposefully limits the size of buffers sent to
 * the wrapped subscriber. This is useful for simulating adverse network conditions.
 */
public class TinyBufferSubscriber implements Subscriber<ByteBuffer> {

    private final Subscriber<? super ByteBuffer> wrappedSubscriber;

    public TinyBufferSubscriber(final Subscriber wrappedSubscriber){
        this.wrappedSubscriber =  wrappedSubscriber;
    }

    @Override
    public void onSubscribe(Subscription s) {
        wrappedSubscriber.onSubscribe(s);
    }

    @Override
    public void onNext(ByteBuffer b) {
        int i = 0;
        // any value below GCM block size works
        int chunkSize = 5;
        while (b.remaining() > chunkSize) {
            ByteBuffer tb = b.slice();
            tb.limit(chunkSize);
            byte[] intermediateBuf = BinaryUtils.copyBytesFrom(tb, chunkSize);
            b.position(i + chunkSize);
            i += chunkSize;
            wrappedSubscriber.onNext(ByteBuffer.wrap(intermediateBuf));
        }
        // send the rest of the bytes
        ByteBuffer sb = b.slice();
        sb.limit(b.remaining());
        byte[] intermedBuf = BinaryUtils.copyBytesFrom(sb, chunkSize);
        wrappedSubscriber.onNext(ByteBuffer.wrap(intermedBuf));
    }

    @Override
    public void onError(Throwable t) {
        wrappedSubscriber.onError(t);
    }

    @Override
    public void onComplete() {
        wrappedSubscriber.onComplete();
    }
}
