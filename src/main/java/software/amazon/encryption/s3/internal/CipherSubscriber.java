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
    private final AtomicLong outstandingRequests = new AtomicLong(0);

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
        System.out.println("[CipherSubscriber] onSubscribe called with subscription: " + s);
        wrappedSubscriber.onSubscribe(new Subscription() {
            @Override
            public void request(long n) {
                System.out.println("[CipherSubscriber] New request received for " + n + " items");
                outstandingRequests.addAndGet(n);
                System.out.println("[CipherSubscriber] Current outstanding requests: " + outstandingRequests.get());
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
        System.out.println("[CipherSubscriber] ByteBuffer content: " + byteBuffer.toString());
//        while (byteBuffer.hasRemaining()) {
//            byte b = byteBuffer.get();
//            System.out.printf("%02x ", b); // Print as hex
//        }
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
                System.out.println("[CipherSubscriber] contentRead: " + contentRead.get() + ", contentLength: " + contentLength);
                if (contentRead.get() == contentLength) {
                    System.out.println("[CipherSubscriber] All content read (contentRead: " + contentRead.get() + ", contentLength: " + contentLength + "), calling onComplete");
                    this.onComplete();
                }
                System.out.println("[CipherSubscriber] Sending empty buffer to wrapped subscriber");
                wrappedSubscriber.onNext(ByteBuffer.allocate(0));
            } else {
                System.out.println("[CipherSubscriber] Sending " + outputBuffer.length + " bytes to wrapped subscriber");
                System.out.println("[CipherSubscriber] contentRead: " + contentRead.get() + ", contentLength: " + contentLength);
                Long amount = isLastPart ? contentLength - 31 : contentLength - 15;
                if (contentRead.get() < amount) {
                    wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
                } else {
                    System.out.println("[CipherSubscriber] All content read (contentRead: " + contentRead.get() + ", contentLength: " + contentLength + "), waiting for onComplete");
//                    this.onComplete();
                }
            }
        } else {
            System.out.println("[CipherSubscriber] No bytes to read from input buffer, forwarding original buffer");
            wrappedSubscriber.onNext(byteBuffer);
        }
    }

    private int getAmountToReadFromByteBuffer(ByteBuffer byteBuffer) {
        System.out.println("[CipherSubscriber] getAmountToReadFromByteBuffer called with buffer remaining: " + byteBuffer.remaining());
        System.out.println("[CipherSubscriber] Current contentRead: " + contentRead.get() + ", contentLength: " + contentLength);

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
        if (onCompleteCalled) {
            return;
        }
        onCompleteCalled = true;
        System.out.println("[CipherSubscriber] onComplete called, isLastPart: " + isLastPart);
        if (!isLastPart) {
            System.out.println("[CipherSubscriber] Not last part, skipping doFinal");
            wrappedSubscriber.onNext(ByteBuffer.wrap(outputBuffer));
            wrappedSubscriber.onComplete();
            return;
        }
        byte[] finalBytes;
        try {
            System.out.println("[CipherSubscriber] Calling cipher.doFinal()");
            finalBytes = cipher.doFinal();
        } catch (final GeneralSecurityException exception) {
            System.out.println("[CipherSubscriber] Error during doFinal: " + exception.getMessage());
            wrappedSubscriber.onError(exception);
            throw new S3EncryptionClientSecurityException(exception.getMessage(), exception);
        }
        System.out.println("[CipherSubscriber] doFinal produced " + (finalBytes != null ? finalBytes.length : 0) + " bytes");

        byte[] combinedBytes;
        if (outputBuffer != null && outputBuffer.length > 0 && finalBytes != null && finalBytes.length > 0) {
            System.out.println("[CipherSubscriber] Combining outputBuffer (" + outputBuffer.length + " bytes) with finalBytes (" + finalBytes.length + " bytes)");
            combinedBytes = new byte[outputBuffer.length + finalBytes.length];
            System.arraycopy(outputBuffer, 0, combinedBytes, 0, outputBuffer.length);
            System.arraycopy(finalBytes, 0, combinedBytes, outputBuffer.length, finalBytes.length);
        } else if (outputBuffer != null && outputBuffer.length > 0) {
            System.out.println("[CipherSubscriber] Using only outputBuffer (" + outputBuffer.length + " bytes)");
            combinedBytes = outputBuffer;
        } else if (finalBytes != null && finalBytes.length > 0) {
            System.out.println("[CipherSubscriber] Using only finalBytes (" + finalBytes.length + " bytes)");
            combinedBytes = finalBytes;
        } else {
            System.out.println("[CipherSubscriber] No bytes to send");
            combinedBytes = new byte[0];
        }

        if (combinedBytes.length > 0) {
            System.out.println("[CipherSubscriber] Sending combined bytes to wrapped subscriber of length " + combinedBytes.length);
            wrappedSubscriber.onNext(ByteBuffer.wrap(combinedBytes));
        }
        System.out.println("[CipherSubscriber] Completing wrapped subscriber");
        wrappedSubscriber.onComplete();
    }

}