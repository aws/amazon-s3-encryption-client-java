// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.utils.BinaryUtils;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.S3EncryptionClientSecurityException;
import software.amazon.encryption.s3.materials.CryptographicMaterials;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A subscriber which decrypts data by buffering the object's contents
 * so that authentication can be done before any plaintext is released.
 * This prevents "release of unauthenticated plaintext" at the cost of
 * allocating a large buffer.
 */
public class BufferedCipherSubscriber implements Subscriber<ByteBuffer> {

    private final AtomicInteger contentRead = new AtomicInteger(0);
    private final AtomicBoolean doneFinal = new AtomicBoolean(false);
    private final Subscriber<? super ByteBuffer> wrappedSubscriber;
    private final int contentLength;
    private Cipher cipher;
    private final CryptographicMaterials materials;
    private final byte[] iv;

    private byte[] outputBuffer;
    private final Queue<ByteBuffer> buffers = new ConcurrentLinkedQueue<>();

    BufferedCipherSubscriber(Subscriber<? super ByteBuffer> wrappedSubscriber, Long contentLength, CryptographicMaterials materials, byte[] iv, long bufferSizeInBytes) {
        this.wrappedSubscriber = wrappedSubscriber;
        if (contentLength == null) {
            throw new S3EncryptionClientException("contentLength cannot be null in buffered mode. To enable unbounded " +
                    "streaming, reconfigure the S3 Encryption Client with Delayed Authentication mode enabled.");
        }
        if (contentLength > bufferSizeInBytes) {
            throw new S3EncryptionClientException(String.format("The object you are attempting to decrypt exceeds the maximum buffer size: " + bufferSizeInBytes +
                    " for the default (buffered) mode. Either increase your buffer size when configuring your client, " +
                    "or enable Delayed Authentication mode to disable buffered decryption."));

        }
        this.contentLength = Math.toIntExact(contentLength);
        this.materials = materials;
        this.iv = iv;
        cipher = materials.getCipher(iv);
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
            try {
                outputBuffer = cipher.update(buf, 0, amountToReadFromByteBuffer);
            } catch (final IllegalStateException exception) {
                // This happens when the stream is reset and the cipher is reused with the
                // same key/IV. It's actually fine here, because the data is the same, but any
                // sane implementation will throw an exception.
                // Request a new cipher using the same materials to avoid reinit issues
                cipher = CipherProvider.createAndInitCipher(materials, iv);
            }

            if (outputBuffer == null && amountToReadFromByteBuffer < cipher.getBlockSize()) {
                // The underlying data is too short to fill in the block cipher
                // This is true at the end of the file, so complete to get the final
                // bytes
                this.onComplete();
            }

            // Enqueue the buffer until all data is read
            buffers.add(ByteBuffer.wrap(outputBuffer));

            // Sometimes, onComplete won't be called, so we check if all
            // data is read to avoid hanging indefinitely
            if (contentRead.get() == contentLength) {
                this.onComplete();
            }
            // This avoids the subscriber waiting indefinitely for more data
            // without actually releasing any plaintext before it can be authenticated
            wrappedSubscriber.onNext(ByteBuffer.allocate(0));
        }

    }

    private int getAmountToReadFromByteBuffer(ByteBuffer byteBuffer) {

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
        if (doneFinal.get()) {
            // doFinal has already been called, bail out
            return;
        }
        try {
            outputBuffer = cipher.doFinal();
            doneFinal.set(true);
            // Once doFinal is called, then we can release the plaintext
            if (contentRead.get() == contentLength) {
                while (!buffers.isEmpty()) {
                    wrappedSubscriber.onNext(buffers.remove());
                }
            }
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
