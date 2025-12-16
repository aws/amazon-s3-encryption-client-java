// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import org.junit.jupiter.api.Test;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CipherSubscriberTest {

    // Use a common static IV
    private static final byte[] _iv = new byte[12];

    static {
        _iv[0] = 1;
    }

    // Helper classes for testing
    class SimpleSubscriber implements Subscriber<ByteBuffer> {

        public static final long DEFAULT_REQUEST_SIZE = 1;

        private final AtomicBoolean isSubscribed = new AtomicBoolean(false);
        private final AtomicLong requestedItems = new AtomicLong(0);
        private final AtomicLong lengthOfData = new AtomicLong(0);
        private final LinkedList<ByteBuffer> buffersSeen = new LinkedList<>();
        private Subscription subscription;

        @Override
        public void onSubscribe(Subscription s) {
            if (isSubscribed.compareAndSet(false, true)) {
                this.subscription = s;
                requestMore(DEFAULT_REQUEST_SIZE);
            } else {
                s.cancel();
            }
        }

        @Override
        public void onNext(ByteBuffer item) {
            // Process the item here
            lengthOfData.addAndGet(item.capacity());
            buffersSeen.add(item);

            // Request the next item
            requestMore(1);
        }

        @Override
        public void onError(Throwable t) {
            System.err.println("Error occurred: " + t.getMessage());
        }

        @Override
        public void onComplete() {
            // Do nothing.
        }

        public void cancel() {
            if (isSubscribed.getAndSet(false)) {
                subscription.cancel();
            }
        }

        private void requestMore(long n) {
            if (subscription != null) {
                requestedItems.addAndGet(n);
                subscription.request(n);
            }
        }

        public List<ByteBuffer> getBuffersSeen() {
            return buffersSeen;
        }
    }

    class TestPublisher<T> {
        private final List<Subscriber<T>> subscribers = new ArrayList<>(1);

        public void subscribe(Subscriber<T> subscriber) {
            subscribers.add(subscriber);
            subscriber.onSubscribe(new TestSubscription());
        }

        public void emit(T item) {
            subscribers.forEach(s -> s.onNext(item));
        }

        public void complete() {
            subscribers.forEach(Subscriber::onComplete);
        }

        public boolean isSubscribed() {
            return !subscribers.isEmpty();
        }

        public int getSubscriberCount() {
            return subscribers.size();
        }
    }

    class TestSubscription implements Subscription {
        private long requestCount = 0;
        private final AtomicBoolean canceled = new AtomicBoolean(false);

        @Override
        public void request(long n) {
            if (!canceled.get()) {
                requestCount += n;
            } else {
                // Maybe do something more useful/correct eventually,
                // for now just throw an exception
                throw new RuntimeException("Subscription has been canceled!");
            }
        }

        @Override
        public void cancel() {
            canceled.set(true);
        }

        public long getRequestCount() {
            return requestCount;
        }
    }

    private EncryptionMaterials getTestEncryptMaterials(String plaintext) {
        try {
            SecretKey AES_KEY;
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            AES_KEY = keyGen.generateKey();
            EncryptionMaterials materials = EncryptionMaterials.builder()
                    .plaintextDataKey(AES_KEY.getEncoded())
                    .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .plaintextLength(plaintext.getBytes(StandardCharsets.UTF_8).length)
                    .build();
            if (materials.algorithmSuite().isCommitting()) {
                // Set MessageId or IV
                materials.setIvAndMessageId(new byte[12], _iv);
            } else {
                materials.setIvAndMessageId(_iv, null);
            }
            return materials;
        } catch (NoSuchAlgorithmException exception) {
            // this should never happen
            throw new RuntimeException("AES doesn't exist");
        }
    }

    private DecryptionMaterials getTestDecryptionMaterialsFromEncMats(EncryptionMaterials encMats) {
        return DecryptionMaterials.builder()
                .plaintextDataKey(encMats.plaintextDataKey())
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .ciphertextLength(encMats.getCiphertextLength())
                .build();
    }

    private byte[] getByteArrayFromFixedLengthByteBuffers(List<ByteBuffer> byteBuffers, long expectedLength) {
        if (expectedLength > Integer.MAX_VALUE) {
            throw new RuntimeException("Use a smaller expected length.");
        }
        return getByteArrayFromFixedLengthByteBuffers(byteBuffers, (int) expectedLength);
    }

    private byte[] getByteArrayFromFixedLengthByteBuffers(List<ByteBuffer> byteBuffers, int expectedLength) {
        byte[] bytes = new byte[expectedLength];
        int offset = 0;
        for (ByteBuffer bb : byteBuffers) {
            int remaining = bb.remaining();
            bb.get(bytes, offset, remaining);
            offset += remaining;
        }
        return bytes;
    }

    @Test
    public void testSubscriberBehaviorOneChunk() {
        AlgorithmSuite algorithmSuite = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
        String plaintext = "unit test of cipher subscriber";
        EncryptionMaterials materials = getTestEncryptMaterials(plaintext);
        SimpleSubscriber wrappedSubscriber = new SimpleSubscriber();
        CipherSubscriber subscriber = new CipherSubscriber(wrappedSubscriber, materials.getCiphertextLength(), materials, materials.iv(), materials.messageId());

        // Act
        TestPublisher<ByteBuffer> publisher = new TestPublisher<>();
        publisher.subscribe(subscriber);

        // Verify subscription behavior
        assertTrue(publisher.isSubscribed());
        assertEquals(1, publisher.getSubscriberCount());

        ByteBuffer ptBb = ByteBuffer.wrap(plaintext.getBytes(StandardCharsets.UTF_8));
        publisher.emit(ptBb);

        // Complete the stream
        publisher.complete();

        long expectedLength = plaintext.getBytes(StandardCharsets.UTF_8).length + algorithmSuite.cipherTagLengthBytes();
        assertEquals(expectedLength, wrappedSubscriber.lengthOfData.get());
        byte[] ctBytes = getByteArrayFromFixedLengthByteBuffers(wrappedSubscriber.getBuffersSeen(), expectedLength);

        // Now decrypt.
        DecryptionMaterials decryptionMaterials = getTestDecryptionMaterialsFromEncMats(materials);
        SimpleSubscriber wrappedDecryptSubscriber = new SimpleSubscriber();
        CipherSubscriber decryptSubscriber = new CipherSubscriber(wrappedDecryptSubscriber, expectedLength, decryptionMaterials, materials.iv(), materials.messageId());
        TestPublisher<ByteBuffer> decryptPublisher = new TestPublisher<>();
        decryptPublisher.subscribe(decryptSubscriber);

        // Verify subscription behavior
        assertTrue(decryptPublisher.isSubscribed());
        assertEquals(1, decryptPublisher.getSubscriberCount());

        // Simulate publishing items
        ByteBuffer ctBb = ByteBuffer.wrap(ctBytes);
        decryptPublisher.emit(ctBb);

        // Complete the stream
        decryptPublisher.complete();

        long expectedLengthPt = plaintext.getBytes(StandardCharsets.UTF_8).length;
        assertEquals(expectedLengthPt, wrappedDecryptSubscriber.lengthOfData.get());
        byte[] ptBytes = getByteArrayFromFixedLengthByteBuffers(wrappedDecryptSubscriber.getBuffersSeen(), expectedLengthPt);
        // Assert round trip encrypt/decrypt succeeds.
        assertEquals(plaintext, new String(ptBytes, StandardCharsets.UTF_8));
    }

    @Test
    public void testSubscriberBehaviorTagLengthLastChunk() {
        AlgorithmSuite algorithmSuite = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
        String plaintext = "unit test of cipher subscriber tag length last chunk";
        EncryptionMaterials materials = getTestEncryptMaterials(plaintext);
        byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];
        // we reject 0-ized IVs, so just do something non-zero
        iv[0] = 1;
        SimpleSubscriber wrappedSubscriber = new SimpleSubscriber();
        CipherSubscriber subscriber = new CipherSubscriber(wrappedSubscriber, materials.getCiphertextLength(), materials, iv, materials.messageId());

        // Setup Publisher
        TestPublisher<ByteBuffer> publisher = new TestPublisher<>();
        publisher.subscribe(subscriber);

        // Verify subscription behavior
        assertTrue(publisher.isSubscribed());
        assertEquals(1, publisher.getSubscriberCount());

        // Send data to be encrypted
        ByteBuffer ptBb = ByteBuffer.wrap(plaintext.getBytes(StandardCharsets.UTF_8));
        publisher.emit(ptBb);
        publisher.complete();

        // Convert to byte array for convenience
        long expectedLength = plaintext.getBytes(StandardCharsets.UTF_8).length + algorithmSuite.cipherTagLengthBytes();
        assertEquals(expectedLength, wrappedSubscriber.lengthOfData.get());
        byte[] ctBytes = getByteArrayFromFixedLengthByteBuffers(wrappedSubscriber.getBuffersSeen(), expectedLength);

        // Now decrypt the ciphertext
        DecryptionMaterials decryptionMaterials = getTestDecryptionMaterialsFromEncMats(materials);
        SimpleSubscriber wrappedDecryptSubscriber = new SimpleSubscriber();
        CipherSubscriber decryptSubscriber = new CipherSubscriber(wrappedDecryptSubscriber, expectedLength, decryptionMaterials, iv, materials.messageId());
        TestPublisher<ByteBuffer> decryptPublisher = new TestPublisher<>();
        decryptPublisher.subscribe(decryptSubscriber);

        // Verify subscription behavior
        assertTrue(decryptPublisher.isSubscribed());
        assertEquals(1, decryptPublisher.getSubscriberCount());

        int taglength = algorithmSuite.cipherTagLengthBytes();
        int ciphertextWithoutTagLength = ctBytes.length - taglength;

        // Create the main ByteBuffer (all except last 16 bytes)
        ByteBuffer mainBuffer = ByteBuffer.allocate(ciphertextWithoutTagLength);
        mainBuffer.put(ctBytes, 0, ciphertextWithoutTagLength);
        mainBuffer.flip();

        // Create the tag ByteBuffer (last 16 bytes)
        ByteBuffer tagBuffer = ByteBuffer.allocate(taglength);
        tagBuffer.put(ctBytes, ciphertextWithoutTagLength, taglength);
        tagBuffer.flip();

        // Send the ciphertext, then the tag separately
        decryptPublisher.emit(mainBuffer);
        decryptPublisher.emit(tagBuffer);
        decryptPublisher.complete();

        long expectedLengthPt = plaintext.getBytes(StandardCharsets.UTF_8).length;
        assertEquals(expectedLengthPt, wrappedDecryptSubscriber.lengthOfData.get());
        byte[] ptBytes = getByteArrayFromFixedLengthByteBuffers(wrappedDecryptSubscriber.getBuffersSeen(), expectedLengthPt);
        // Assert round trip encrypt/decrypt succeeds
        assertEquals(plaintext, new String(ptBytes, StandardCharsets.UTF_8));
    }
}