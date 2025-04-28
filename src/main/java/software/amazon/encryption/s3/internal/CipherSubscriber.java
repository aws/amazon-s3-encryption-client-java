// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.utils.BinaryUtils;
import software.amazon.encryption.s3.S3EncryptionClientSecurityException;
import software.amazon.encryption.s3.materials.CryptographicMaterials;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.concurrent.atomic.AtomicLong;

public class CipherSubscriber implements Subscriber<ByteBuffer> {
    private final AtomicLong contentRead = new AtomicLong(0);
    private final Subscriber<? super ByteBuffer> wrappedSubscriber;
    private Cipher cipher;
    private final Long contentLength;
    private boolean isLastPart;
    private boolean onCompleteCalled = false;

    private byte[] outputBuffer;

    CipherSubscriber(Subscriber<? super ByteBuffer> wrappedSubscriber, Long contentLength, CryptographicMaterials materials, byte[] iv, boolean isLastPart) {
        this.wrappedSubscriber = wrappedSubscriber;
        this.contentLength = contentLength;
        cipher = materials.getCipher(iv);
        this.isLastPart = isLastPart;
    }

    CipherSubscriber(Subscriber<? super ByteBuffer> wrappedSubscriber, Long contentLength, CryptographicMaterials materials, byte[] iv) {
        // When no partType is specified, it's not multipart, so there's one part, which must be the last
        this(wrappedSubscriber, contentLength, materials, iv, true);
    }

    @Override
    public void onSubscribe(Subscription s) {
        wrappedSubscriber.onSubscribe(s);
    }

    @Override
    public void onNext(ByteBuffer byteBuffer) {
        int amountToReadFromByteBuffer = getAmountToReadFromByteBuffer(byteBuffer);

        if (amountToReadFromByteBuffer > 0) {
            byte[] buf = BinaryUtils.copyBytesFrom(byteBuffer, amountToReadFromByteBuffer);
            outputBuffer = cipher.update(buf, 0, amountToReadFromByteBuffer);

            if (outputBuffer == null || outputBuffer.length == 0) {
                // The underlying data is too short to fill in the block cipher.
                // Note that while the JCE Javadoc specifies that the outputBuffer is null in this case,
                // in practice SunJCE and ACCP return an empty buffer instead, hence checks for
                // null OR length == 0.
                if (contentRead.get() == contentLength) {
                    // All content has been read, so complete to get the final bytes
                    this.onComplete();
                }
                // Otherwise, wait for more bytes. To avoid blocking,
                // send an empty buffer to the wrapped subscriber.
                wrappedSubscriber.onNext(ByteBuffer.allocate(0));
            } else {
                // cipher.update will only return a block of data if it has been provided a full block of data.
                // If it has been provided a partial block of data, it will not return partial data.
                // If the CipherSubscriber is done sending data, but the total amount of data is not a multiple of the block size,
                // the amount of content returned by the cipher will be less than the contentLength by at most the block size.
                // Calling `doFinal` will return the remaining bytes along with the tag.
                Long amount = contentLength - cipher.getBlockSize();
                if (contentRead.get() < amount) {
                    // If the amount of data read so far is less than the amount of data that should have been read,
                    // send the data downstream, expecting that downstream will request more data.
                    wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
                } else {
                    // If the amount of data read so far is at least the amount of data that should have been read,
                    // complete the stream, as downstream will not request any more data.
                    this.onComplete();
                }
            }
        } else {
            // Do nothing
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
        wrappedSubscriber.onError(t);
    }

    @Override
    public void onComplete() {
        if (onCompleteCalled) {
            return;
        }
        onCompleteCalled = true;
        if (!isLastPart) {
            // If this isn't the last part, skip doFinal, we aren't done
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
            wrappedSubscriber.onComplete();
            return;
        }

        byte[] finalBytes = null;
        try {
            finalBytes = cipher.doFinal();
        } catch (final GeneralSecurityException exception) {
            // Even if doFinal fails, downstream still expects to receive the bytes that were in outputBuffer
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
            // Forward error, else the wrapped subscriber waits indefinitely
            wrappedSubscriber.onError(exception);
            // Even though doFinal failed, downstream still expects to receive onComplete signal
            wrappedSubscriber.onComplete();
            throw new S3EncryptionClientSecurityException(exception.getMessage(), exception);
        }

        // Combine the bytes from outputBuffer and finalBytes into one onNext call.
        // Downstream has requested `1` in its request method, so this class can only call onNext once.
        // This onNext call must contain both the bytes from outputBuffer and the tag.
        byte[] combinedBytes;
        if (outputBuffer != null && outputBuffer.length > 0 && finalBytes != null && finalBytes.length > 0) {
            combinedBytes = new byte[outputBuffer.length + finalBytes.length];
            System.arraycopy(outputBuffer, 0, combinedBytes, 0, outputBuffer.length);
            System.arraycopy(finalBytes, 0, combinedBytes, outputBuffer.length, finalBytes.length);
        } else if (outputBuffer != null && outputBuffer.length > 0) {
            combinedBytes = outputBuffer;
        } else if (finalBytes != null && finalBytes.length > 0) {
            combinedBytes = finalBytes;
        } else {
            combinedBytes = new byte[0];
        }

        if (combinedBytes.length > 0) {
            wrappedSubscriber.onNext(ByteBuffer.wrap(combinedBytes));
        }
        wrappedSubscriber.onComplete();
    }

}