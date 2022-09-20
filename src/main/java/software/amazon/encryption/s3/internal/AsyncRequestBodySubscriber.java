package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.internal.async.ByteArrayAsyncRequestBody;
import software.amazon.awssdk.core.internal.async.FileAsyncRequestBody;
import software.amazon.encryption.s3.S3EncryptionClientException;

import java.nio.ByteBuffer;

public class AsyncRequestBodySubscriber {

    private Subscription subscription;
    private ByteBuffer byteBuffer;

    public ByteBuffer getByteBuffer(AsyncRequestBody asyncRequestBody) {
        if(asyncRequestBody instanceof ByteArrayAsyncRequestBody) {
            asyncRequestBody.subscribe(byteArraySubscriber);
        }
        else if(asyncRequestBody instanceof FileAsyncRequestBody) {
            // TODO: FileAsyncRequestBody Subscriber implementation
            asyncRequestBody.subscribe(fileSubscriber);
         }
        return byteBuffer;

    }

    private Subscriber<ByteBuffer> byteArraySubscriber = new Subscriber<ByteBuffer>() {
        @Override
        public void onSubscribe(Subscription s) {
            subscription = s;
            subscription.request(1);
        }

        @Override
        public void onNext(ByteBuffer b) {
            byteBuffer = b;
        }

        @Override
        public void onError(Throwable t) {
            throw new S3EncryptionClientException("" + t);
        }

        @Override
        public void onComplete() {
        }
    };

    // TODO: FileAsyncRequestBody Subscriber implementation
    private Subscriber<ByteBuffer> fileSubscriber = new Subscriber<ByteBuffer>() {
        @Override
        public void onSubscribe(Subscription s) {
            subscription = s;
            subscription.request(1);
        }

        @Override
        public void onNext(ByteBuffer b) {
            byteBuffer = b;
        }

        @Override
        public void onError(Throwable t) {
            throw new S3EncryptionClientException("" + t);
        }

        @Override
        public void onComplete() {
        }
    };
}
