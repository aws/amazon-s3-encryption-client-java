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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class CipherSubscriber implements Subscriber<ByteBuffer> {
    private final AtomicLong contentRead = new AtomicLong(0);
    private final Subscriber<? super ByteBuffer> wrappedSubscriber;
    private final Cipher cipher;
    private final Long contentLength;
    private final boolean isLastPart;
    private final int tagLength;
    private final boolean isEncrypt;
    private final AtomicBoolean finalBytesCalled = new AtomicBoolean(false);

    private byte[] outputBuffer;

    CipherSubscriber(Subscriber<? super ByteBuffer> wrappedSubscriber, Long contentLength, CryptographicMaterials materials, byte[] iv, boolean isLastPart) {
        this.wrappedSubscriber = wrappedSubscriber;
        this.contentLength = contentLength;
        this.cipher = materials.getCipher(iv);
        this.isLastPart = isLastPart;
        this.tagLength = materials.algorithmSuite().cipherTagLengthBytes();
        this.isEncrypt = (CipherMode.DECRYPT != materials.cipherMode());
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

                // tagLength should only be added on Encrypt
                if (contentRead.get() + (isEncrypt ? tagLength : 0) >= contentLength) {
                    // All content has been read, so complete to get the final bytes
                    finalBytes();
                    return;
                }
                // Otherwise, wait for more bytes. To avoid blocking,
                // send an empty buffer to the wrapped subscriber.
                wrappedSubscriber.onNext(ByteBuffer.allocate(0));
            } else {
                /*
                 Check if stream has read all expected content.
                 Once all content has been read, call `finalBytes`.

                 This determines that all content has been read by checking if
                 the amount of data read so far plus the tag length is at least the content length.
                 Once this is true, downstream will never call `request` again
                 (beyond the current request that is being responded to in this onNext invocation.)
                 As a result, this class can only call `wrappedSubscriber.onNext` one more time.
                 (Reactive streams require that downstream sends a `request(n)`
                 to indicate it is ready for more data, and upstream responds to that request by calling `onNext`.
                 The `n` in request is the maximum number of `onNext` calls that downstream
                 will allow upstream to make, and seems to always be 1 for the AsyncBodySubscriber.)
                 Since this class can only call `wrappedSubscriber.onNext` once,
                 it must send all remaining data in the next onNext call,
                 including the result of cipher.doFinal(), if applicable.
                 Calling `wrappedSubscriber.onNext` more than once for `request(1)`
                 violates the Reactive Streams specification and can cause exceptions downstream.
                */
                if (contentRead.get() + (isEncrypt ? tagLength : 0) >= contentLength) {
                    // All content has been read; complete the stream.
                    finalBytes();
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
        // In rare cases, e.g. when the last part of a low-level MPU has 0 length,
        // onComplete will be called before onNext is called once.
        // So, call finalBytes here just in case there's any unsent data left.
        // Most likely, finalBytes has already been called by the last onNext,
        // but finalBytes guards against multiple invocations so it's safe to call again.
        finalBytes();
        wrappedSubscriber.onComplete();
    }

    /**
     * Finalize encryption, including calculating the auth tag for AES-GCM.
     * As such this method MUST only be called once, which is enforced using
     * `finalBytesCalled`.
     */
    private void finalBytes() {
        if (!finalBytesCalled.compareAndSet(false, true)) {
            // already called, don't repeat
            return;
        }

        // If this isn't the last part, skip doFinal and just send outputBuffer downstream.
        // doFinal requires that all parts have been processed to compute the tag,
        // so the tag will only be computed when the last part is processed.
        if (!isLastPart) {
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
            return;
        }

        // If this is the last part, compute doFinal and include its result in the value sent downstream.
        // The result of doFinal MUST be included with the bytes that were in outputBuffer in the final onNext call.
        byte[] finalBytes;
        try {
            finalBytes = cipher.doFinal();
        } catch (final GeneralSecurityException exception) {
            // Even if doFinal fails, downstream still expects to receive the bytes that were in outputBuffer
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
            // Forward error, else the wrapped subscriber waits indefinitely
            wrappedSubscriber.onError(exception);
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
    }

}