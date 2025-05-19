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
    // Helper classes for testing
    class MySubscriber implements Subscriber<ByteBuffer> {

        public static final long DEFAULT_REQUEST_SIZE = 1;

        private final AtomicBoolean isSubscribed = new AtomicBoolean(false);
        private final AtomicLong requestedItems = new AtomicLong(0);
        private final AtomicLong lengthOfData = new AtomicLong(0);
        private LinkedList<ByteBuffer> buffersSeen = new LinkedList<>();
        private Subscription subscription;

        @Override
        public void onSubscribe(Subscription s) {
            if (isSubscribed.compareAndSet(false, true)) {
                this.subscription = s;
                requestMore(DEFAULT_REQUEST_SIZE);
            } else {
                s.cancel(); // Cancel the new subscription if we're already subscribed
            }
        }

        @Override
        public void onNext(ByteBuffer item) {
            // Process the item here
            System.out.println("Received: " + item);
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
            System.out.println("Stream completed");
        }

        public void cancel() {
            if (isSubscribed.getAndSet(false)) {
                subscription.cancel();
            }
        }

        private void requestMore(long n) {
            if (subscription != null) {
                System.out.println("Requesting more...");
                requestedItems.addAndGet(n);
                subscription.request(n);
            }
        }

        // Getter methods for testing
        public boolean isSubscribed() {
            return isSubscribed.get();
        }

        public List<ByteBuffer> getBuffersSeen() {
            return buffersSeen;
        }
    }

    class TestPublisher<T> {
        private List<Subscriber<T>> subscribers = new ArrayList<>();

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
        private long requestedItems = 0;

        @Override
        public void request(long n) {
            System.out.println("received req for " + n);
            requestedItems += n;
            System.out.println("total req'd items is " + requestedItems);
        }

        @Override
        public void cancel() {
            // Implementation for testing cancel behavior
        }

        public long getRequestedItems() {
            return requestedItems;
        }
    }

    private EncryptionMaterials getTestEncryptMaterials(String plaintext) {
        try {
            SecretKey AES_KEY;
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            AES_KEY = keyGen.generateKey();
            return EncryptionMaterials.builder()
                    .plaintextDataKey(AES_KEY.getEncoded())
                    .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .plaintextLength(plaintext.getBytes(StandardCharsets.UTF_8).length)
                    .build();
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

    @Test
    public void testSubscriberBehavior() throws InterruptedException {
        String plaintext = "unit test of cipher subscriber";
        EncryptionMaterials materials = getTestEncryptMaterials(plaintext);
        byte[] iv = new byte[materials.algorithmSuite().iVLengthBytes()];
        // we reject 0-ized IVs, so just do something
        iv[0] = 1;
        MySubscriber wrappedSubscriber = new MySubscriber();
        CipherSubscriber subscriber = new CipherSubscriber(wrappedSubscriber, (long) plaintext.getBytes(StandardCharsets.UTF_8).length, materials, iv);

        // Arrange
        // TODO: These need to be moved probably to the wrappedSubscriber,
        // so they are actually updated as the subscription is processed.
//        CountDownLatch completionLatch = new CountDownLatch(1);
//        AtomicInteger receivedItems = new AtomicInteger(0);
//        AtomicInteger errorCount = new AtomicInteger(0);

        // Act
        TestPublisher<ByteBuffer> publisher = new TestPublisher<>();
        publisher.subscribe(subscriber);

        // Verify subscription behavior
        assertTrue(publisher.isSubscribed());
        assertEquals(1, publisher.getSubscriberCount());

        // Simulate publishing items
//        publisher.emit("item1");
        ByteBuffer ptBb = ByteBuffer.wrap(plaintext.getBytes(StandardCharsets.UTF_8));
        System.out.println("emitting...");
        publisher.emit(ptBb);
        System.out.println("emitted");

        // Complete the stream
        System.out.println("completing...");
        publisher.complete();
        System.out.println("completed.");

        // Assert
//        assertTrue(completionLatch.await(5, TimeUnit.SECONDS));
//        assertEquals(1, wrappedSubscriber.getRequestedItems());
//        assertEquals(0, errorCount.get());
        long expectedLength = plaintext.getBytes(StandardCharsets.UTF_8).length + AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherTagLengthBytes();
        assertEquals(expectedLength, wrappedSubscriber.lengthOfData.get());
        byte[] ctBytes = new byte[(int) expectedLength];
        int offset = 0;
        for (ByteBuffer bb : wrappedSubscriber.getBuffersSeen()) {
            int remaining = bb.remaining();
            bb.get(ctBytes, offset, remaining);
            offset += remaining;
        }

        // Now decrypt.
        DecryptionMaterials decryptionMaterials = getTestDecryptionMaterialsFromEncMats(materials);
        MySubscriber wrappedDecryptSubscriber = new MySubscriber();
        CipherSubscriber decryptSubscriber = new CipherSubscriber(wrappedDecryptSubscriber, expectedLength, decryptionMaterials, iv);
        TestPublisher<ByteBuffer> decryptPublisher = new TestPublisher<>();
        decryptPublisher.subscribe(decryptSubscriber);

        // Verify subscription behavior
        assertTrue(decryptPublisher.isSubscribed());
        assertEquals(1, decryptPublisher.getSubscriberCount());

        // Simulate publishing items
        ByteBuffer ctBb = ByteBuffer.wrap(ctBytes);
        System.out.println("emitting...");
        decryptPublisher.emit(ctBb);
        System.out.println("emitted");

        // Complete the stream
        System.out.println("completing...");
        decryptPublisher.complete();
        System.out.println("completed.");

        // Assert
        long expectedLengthPt = plaintext.getBytes(StandardCharsets.UTF_8).length;
        assertEquals(expectedLengthPt, wrappedDecryptSubscriber.lengthOfData.get());
        byte[] ptBytes = new byte[(int) expectedLengthPt];
        int offsetPt = 0;
        for (ByteBuffer bb : wrappedDecryptSubscriber.getBuffersSeen()) {
            int remaining = bb.remaining();
            bb.get(ptBytes, offsetPt, remaining);
            offsetPt += remaining;
        }
        // Round trip encrypt/decrypt succeeds.
        assertEquals(plaintext, new String(ptBytes, StandardCharsets.UTF_8));
    }

////    @Test
//    void testBackpressure() {
//        // Arrange
//        CipherSubscriber<ByteBuffer> subscriber = new CipherSubscriber(wrappedSubscriber, contentLength, materials, iv);
//        TestSubscription subscription = new TestSubscription();
//
//        // Act
//        subscriber.onSubscribe(subscription);
//
//        // Assert
//        assertEquals(TestSubscriber.DEFAULT_REQUEST_SIZE, subscription.getRequestedItems());
//    }
//
////    @Test
//    void testErrorHandling() {
//        // Arrange
//        AtomicInteger errorCount = new AtomicInteger(0);
//        MySubscriber<String> subscriber = new MySubscriber<>() {
//            @Override
//            public void onError(Throwable t) {
//                errorCount.incrementAndGet();
//            }
//        };
//
//        // Act
//        subscriber.onError(new RuntimeException("Test error"));
//
//        // Assert
//        assertEquals(1, errorCount.get());
//    }
}

