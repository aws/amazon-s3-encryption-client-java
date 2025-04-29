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
    private int tagLength;
    private boolean onCompleteCalled = false;

    private byte[] outputBuffer;

    CipherSubscriber(Subscriber<? super ByteBuffer> wrappedSubscriber, Long contentLength, CryptographicMaterials materials, byte[] iv, boolean isLastPart) {
        this.wrappedSubscriber = wrappedSubscriber;
        this.contentLength = contentLength;
        cipher = materials.getCipher(iv);
        this.isLastPart = isLastPart;

        // Determine the tag length based on the cipher algorithm
        if (cipher.getAlgorithm().contains("GCM")) {
            tagLength = 16;
        } else if (cipher.getAlgorithm().contains("CBC") || cipher.getAlgorithm().contains("CTR")) {
            tagLength = 0;
        } else {
            throw new IllegalArgumentException("Unsupported cipher type: " + cipher.getAlgorithm());
        }
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
                // Once all content has been read, call onComplete.
                // This class can identify when all content has been read because the amount of data read so far
                // plus the tag length will equal the content length.
                if (contentRead.get() + tagLength == contentLength) {
                    // All content has been read, so complete the stream.
                    // The next onNext call MUST include all bytes, including the result of cipher.doFinal().
                    // Sending any additional onNext calls violates the Reactive Streams specification
                    // and can lead to issues.
                    this.onComplete();
                } else {
                    // Needs to read more data, so send the data downstream,
                    // expecting that downstream will continue to request more data.
                    wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
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
        // onComplete can be signalled to CipherSubscriber multiple times,
        // but additional calls should be deduped.
        if (onCompleteCalled) {
            return;
        }
        onCompleteCalled = true;

        // If this isn't the last part, skip doFinal and just send outputBuffer downstream.
        if (!isLastPart) {
            // First, propagate the bytes that were in outputBuffer downstream.
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
            // Then, propagate the onComplete signal downstream.
            wrappedSubscriber.onComplete();
            return;
        }

        // If this is the last part, include the result of doFinal in the value sent downstream.
        byte[] finalBytes = null;
        try {
            finalBytes = cipher.doFinal();
        } catch (final GeneralSecurityException exception) {
            // Even if doFinal fails, downstream still expects to receive the bytes that were in outputBuffer
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
            // Forward error, else the wrapped subscriber waits indefinitely
            wrappedSubscriber.onError(exception);
            // Even though doFinal failed, propagate the onComplete signal downstream.
            wrappedSubscriber.onComplete();
            throw new S3EncryptionClientSecurityException(exception.getMessage(), exception);
        }

        // Combine the bytes from outputBuffer and finalBytes into one onNext call.
        // Downstream has requested one item in its request method, so this class can only call onNext once.
        // This single onNext call must contain both the bytes from outputBuffer and the tag.
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

        wrappedSubscriber.onNext(ByteBuffer.wrap(combinedBytes));
        wrappedSubscriber.onComplete();
    }

}