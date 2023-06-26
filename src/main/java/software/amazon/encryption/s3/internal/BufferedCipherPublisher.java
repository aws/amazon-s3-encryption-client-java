// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import software.amazon.awssdk.core.async.SdkPublisher;
import software.amazon.encryption.s3.materials.CryptographicMaterials;

import java.nio.ByteBuffer;

public class BufferedCipherPublisher implements SdkPublisher<ByteBuffer> {

    private final SdkPublisher<ByteBuffer> wrappedPublisher;
    private final Long contentLength;
    private final CryptographicMaterials materials;
    private final byte[] iv;
    private final long bufferSize;

    public BufferedCipherPublisher(final SdkPublisher<ByteBuffer> wrappedPublisher, final Long contentLength,
                                   final CryptographicMaterials materials, final byte[] iv, final long bufferSize) {
        this.wrappedPublisher = wrappedPublisher;
        this.contentLength = contentLength;
        this.materials = materials;
        this.iv = iv;
        this.bufferSize = bufferSize;
    }

    @Override
    public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
        // Wrap the (customer) subscriber in a CipherSubscriber, then subscribe it
        // to the wrapped (ciphertext) publisher
        wrappedPublisher.subscribe(new BufferedCipherSubscriber(subscriber, contentLength, materials, iv, bufferSize));
    }
}
