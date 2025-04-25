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
    private boolean finalized;

    private byte[] outputBuffer;

    CipherSubscriber(Subscriber<? super ByteBuffer> wrappedSubscriber, Long contentLength, CryptographicMaterials materials, byte[] iv, boolean isLastPart) {
        this.wrappedSubscriber = wrappedSubscriber;
        this.contentLength = contentLength;
        cipher = materials.getCipher(iv);
        this.isLastPart = isLastPart;
        this.finalized = false;
    }

    CipherSubscriber(Subscriber<? super ByteBuffer> wrappedSubscriber, Long contentLength, CryptographicMaterials materials, byte[] iv) {
        // When no partType is specified, it's not multipart, so there's one part, which must be the last
        this(wrappedSubscriber, contentLength, materials, iv, true);
    }

    @Override
    public void onSubscribe(Subscription s) {
        System.out.println("[CipherSubscriber] onSubscribe called with subscription: " + s);
        wrappedSubscriber.onSubscribe(new Subscription() {
            @Override
            public void request(long n) {
                System.out.println("[CipherSubscriber] New request received for " + n + " items");
                s.request(n);
            }

            @Override
            public void cancel() {
                System.out.println("[CipherSubscriber] Subscription cancelled");
                s.cancel();
            }
        });
    }

    @Override
    public void onNext(ByteBuffer byteBuffer) {
        System.out.println("[CipherSubscriber] onNext called with buffer size: " + byteBuffer.remaining());
        System.out.println("[CipherSubscriber] isLastPart: " + isLastPart);
        int amountToReadFromByteBuffer = getAmountToReadFromByteBuffer(byteBuffer);
        System.out.println("[CipherSubscriber] amountToReadFromByteBuffer: " + amountToReadFromByteBuffer);

        if (amountToReadFromByteBuffer > 0) {
            System.out.println("[CipherSubscriber] Processing chunk of size: " + amountToReadFromByteBuffer);
            byte[] buf = BinaryUtils.copyBytesFrom(byteBuffer, amountToReadFromByteBuffer);
            System.out.println("[CipherSubscriber] Copied " + buf.length + " bytes from input buffer");
            
            outputBuffer = cipher.update(buf, 0, amountToReadFromByteBuffer);
            System.out.println("[CipherSubscriber] Cipher update produced output buffer of length: " + (outputBuffer != null ? outputBuffer.length : 0));

            if (outputBuffer == null || outputBuffer.length == 0) {
                System.out.println("[CipherSubscriber] No output from cipher update");
                // No bytes provided from upstream; to avoid blocking, send an empty buffer to the wrapped subscriber.
                wrappedSubscriber.onNext(ByteBuffer.allocate(0));
            } else {
                boolean atEnd = isLastPart && contentRead.get() + amountToReadFromByteBuffer >= contentLength;
                System.out.println("[CipherSubscriber] atEnd: " + atEnd + " (contentRead: " + contentRead.get() + ", contentLength: " + contentLength + ")");

                if (atEnd) {
                    System.out.println("[CipherSubscriber] Processing final bytes");
                    // If all content has been read, send the final bytes in this onNext call.
                    // The final bytes must be sent with the final onNext call, not during the onComplete call.
                    byte[] finalBytes;
                    try {
                        finalBytes = cipher.doFinal();
                        finalized = true;
                        System.out.println("[CipherSubscriber] Cipher doFinal produced " + finalBytes.length + " bytes");
                    } catch (final GeneralSecurityException exception) {
                        System.out.println("[CipherSubscriber] Error during doFinal: " + exception.getMessage());
                        wrappedSubscriber.onError(exception);
                        throw new S3EncryptionClientSecurityException(exception.getMessage(), exception);
                    }

                    // Combine outputBuffer and finalBytes if both exist
                    byte[] combinedBuffer;
                    if (outputBuffer != null && outputBuffer.length > 0) {
                        System.out.println("[CipherSubscriber] Combining outputBuffer (" + outputBuffer.length + " bytes) with finalBytes (" + finalBytes.length + " bytes)");
                        combinedBuffer = new byte[outputBuffer.length + finalBytes.length];
                        System.arraycopy(outputBuffer, 0, combinedBuffer, 0, outputBuffer.length);
                        System.arraycopy(finalBytes, 0, combinedBuffer, outputBuffer.length, finalBytes.length);
                        System.out.println("[CipherSubscriber] Combined buffer total length: " + combinedBuffer.length);
                    } else {
                        System.out.println("[CipherSubscriber] Using only finalBytes (" + finalBytes.length + " bytes)");
                        combinedBuffer = finalBytes;
                    }
                    System.out.println("[CipherSubscriber] Sending combined buffer to wrapped subscriber");
                    wrappedSubscriber.onNext(ByteBuffer.wrap(combinedBuffer));
                } else {
                    System.out.println("[CipherSubscriber] Sending " + outputBuffer.length + " bytes to wrapped subscriber");
                    // Not at end; send content so far
                    wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
                }
            }
        } else {
            System.out.println("[CipherSubscriber] No bytes to read from input buffer, forwarding original buffer");
            // Do nothing
            wrappedSubscriber.onNext(byteBuffer);
        }
    }

    private int getAmountToReadFromByteBuffer(ByteBuffer byteBuffer) {
        System.out.println("[CipherSubscriber] getAmountToReadFromByteBuffer called with buffer remaining: " + byteBuffer.remaining());
        System.out.println("[CipherSubscriber] Current contentRead: " + contentRead.get() + ", contentLength: " + contentLength);

        // If content length is null, we should include everything in the cipher because the stream is essentially
        // unbounded.
        if (contentLength == null) {
            System.out.println("[CipherSubscriber] No content length specified, reading entire buffer: " + byteBuffer.remaining());
            return byteBuffer.remaining();
        }

        long amountReadSoFar = contentRead.getAndAdd(byteBuffer.remaining());
        long amountRemaining = Math.max(0, contentLength - amountReadSoFar);
        System.out.println("[CipherSubscriber] amountReadSoFar: " + amountReadSoFar + ", amountRemaining: " + amountRemaining);

        if (amountRemaining > byteBuffer.remaining()) {
            System.out.println("[CipherSubscriber] More remaining than buffer size, reading entire buffer: " + byteBuffer.remaining());
            return byteBuffer.remaining();
        } else {
            System.out.println("[CipherSubscriber] Reading partial buffer: " + amountRemaining);
            return Math.toIntExact(amountRemaining);
        }
    }

    @Override
    public void onError(Throwable t) {
        System.out.println("[CipherSubscriber] onError called: " + t.getMessage());
        wrappedSubscriber.onError(t);
    }

    @Override
    public void onComplete() {
        if (!isLastPart) {
            // If this isn't the last part, skip doFinal, we aren't done
            wrappedSubscriber.onComplete();
            return;
        } if (finalized) {
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