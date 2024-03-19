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
    private final CryptographicMaterials materials;
    private byte[] iv;
    private boolean isLastPart;

    private byte[] outputBuffer;

    CipherSubscriber(Subscriber<? super ByteBuffer> wrappedSubscriber, Long contentLength, CryptographicMaterials materials, byte[] iv, boolean isLastPart) {
        this.wrappedSubscriber = wrappedSubscriber;
        this.contentLength = contentLength;
        this.materials = materials;
        this.iv = iv;
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
                wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
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
        if (!isLastPart) {
            // If this isn't the last part, skip doFinal, we aren't done
            wrappedSubscriber.onComplete();
            return;
        }
        try {
            outputBuffer = cipher.doFinal();
            // Send the final bytes to the wrapped subscriber
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
        } catch (final GeneralSecurityException exception) {
            // Forward error, else the wrapped subscriber waits indefinitely
            wrappedSubscriber.onError(exception);
            throw new S3EncryptionClientSecurityException(exception.getMessage(), exception);
        }
        wrappedSubscriber.onComplete();
    }

}