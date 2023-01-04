package software.amazon.encryption.s3.legacy.internal;

import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class AdjustedRangeSubscriber implements Subscriber<ByteBuffer> {
    private final int SYMMETRIC_CIPHER_BLOCK_SIZE_BYTES = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherBlockSizeBytes();

    private final Subscriber<? super ByteBuffer> wrappedSubscriber;

    private byte[] outputBuffer;
    private long virtualAvailable;
    private int numBytesToSkip = 0;

    public AdjustedRangeSubscriber(Subscriber<? super ByteBuffer> wrappedSubscriber, Long rangeBeginning, Long rangeEnd) throws IOException {
        this.wrappedSubscriber = wrappedSubscriber;
        initializeForRead(rangeBeginning, rangeEnd);
    }

    private void initializeForRead(long rangeBeginning, long rangeEnd) {
        // To get to the left-most byte desired by a user, we must skip over the 16 bytes of the
        // preliminary cipher block, and then possibly skip a few more bytes into the next block
        // to where the left-most byte is located.

        if (rangeBeginning < SYMMETRIC_CIPHER_BLOCK_SIZE_BYTES) {
            numBytesToSkip = (int) rangeBeginning;
        } else {
            int offsetIntoBlock = (int) (rangeBeginning % SYMMETRIC_CIPHER_BLOCK_SIZE_BYTES);
            numBytesToSkip = SYMMETRIC_CIPHER_BLOCK_SIZE_BYTES + offsetIntoBlock;
        }
        // The number of bytes the user may read is equal to the number of the bytes in the range.
        // Note that the range includes the endpoints.
        this.virtualAvailable = (rangeEnd - rangeBeginning) + 1;
    }


    @Override
    public void onSubscribe(Subscription s) {
        wrappedSubscriber.onSubscribe(s);
    }

    @Override
    public void onNext(ByteBuffer byteBuffer) {
        if (numBytesToSkip != 0) {
            byte[] buf = byteBuffer.array();
            if (numBytesToSkip > buf.length) {
                numBytesToSkip -= buf.length;
                // TODO: This Handles CBC mode Edge Condition but not working
                wrappedSubscriber.onNext(ByteBuffer.wrap(new byte[0]));
            } else {
                outputBuffer = Arrays.copyOfRange(buf, numBytesToSkip, buf.length);
                numBytesToSkip = 0;
            }
        } else {
            outputBuffer = byteBuffer.array();
        }

        if (virtualAvailable > 0) {
            long bytesToRead = Math.min(virtualAvailable, outputBuffer.length);
            virtualAvailable -= bytesToRead;
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer, 0, Math.toIntExact(bytesToRead)));
        }
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