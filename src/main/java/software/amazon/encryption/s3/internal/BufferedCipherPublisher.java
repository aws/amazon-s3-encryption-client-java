/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import software.amazon.awssdk.core.async.SdkPublisher;
import software.amazon.encryption.s3.legacy.internal.RangedGetUtils;
import software.amazon.encryption.s3.materials.CryptographicMaterials;

import java.nio.ByteBuffer;

public class BufferedCipherPublisher implements SdkPublisher<ByteBuffer> {

    private final SdkPublisher<ByteBuffer> wrappedPublisher;
    private final Long contentLength;
    private final long[] range;
    private final String contentRange;
    private final int cipherTagLengthBits;
    private final CryptographicMaterials materials;
    private final byte[] iv;

    public BufferedCipherPublisher(final SdkPublisher<ByteBuffer> wrappedPublisher, final Long contentLength,
                                   long[] range, String contentRange, int cipherTagLengthBits,
                                   final CryptographicMaterials materials, final byte[] iv) {
        this.wrappedPublisher = wrappedPublisher;
        this.contentLength = contentLength;
        this.range = range;
        this.contentRange = contentRange;
        this.cipherTagLengthBits = cipherTagLengthBits;
        this.materials = materials;
        this.iv = iv;
    }

    @Override
    public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
        // Wrap the (customer) subscriber in a CipherSubscriber, then subscribe it
        // to the wrapped (ciphertext) publisher
        Subscriber<? super ByteBuffer> wrappedSubscriber = RangedGetUtils.adjustToDesiredRange(subscriber, range,
                contentRange, cipherTagLengthBits);
        wrappedPublisher.subscribe(new BufferedCipherSubscriber(wrappedSubscriber, contentLength, materials, iv));
    }
}
