// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import software.amazon.awssdk.core.async.SdkPublisher;
import software.amazon.encryption.s3.legacy.internal.RangedGetUtils;
import software.amazon.encryption.s3.materials.CryptographicMaterials;

import java.nio.ByteBuffer;

/**
 * A Publisher which encrypts and decrypts data as it passes through
 * using a configured Cipher instance.
 */
public class CipherPublisher implements SdkPublisher<ByteBuffer> {

    private final SdkPublisher<ByteBuffer> wrappedPublisher;
    private final CryptographicMaterials materials;
    private final Long contentLength;
    private final long[] range;
    private final String contentRange;
    private final int cipherTagLengthBits;
    private final byte[] iv;

    public CipherPublisher(final SdkPublisher<ByteBuffer> wrappedPublisher, final Long contentLength, long[] range,
                           String contentRange, int cipherTagLengthBits, final CryptographicMaterials materials, final byte[] iv) {
        this.wrappedPublisher = wrappedPublisher;
        this.materials = materials;
        this.contentLength = contentLength;
        this.range = range;
        this.contentRange = contentRange;
        this.cipherTagLengthBits = cipherTagLengthBits;
        this.iv = iv;
    }

    @Override
    public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
        // Wrap the (customer) subscriber in a CipherSubscriber, then subscribe it
        // to the wrapped (ciphertext) publisher
        Subscriber<? super ByteBuffer> wrappedSubscriber = RangedGetUtils.adjustToDesiredRange(subscriber, range, contentRange, cipherTagLengthBits);
        wrappedPublisher.subscribe(new CipherSubscriber(wrappedSubscriber, contentLength, materials, iv));
    }
}
