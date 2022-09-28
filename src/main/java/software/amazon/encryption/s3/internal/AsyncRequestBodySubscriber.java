package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.internal.async.ByteArrayAsyncRequestBody;
import software.amazon.awssdk.core.internal.async.FileAsyncRequestBody;
import software.amazon.awssdk.core.internal.async.FileAsyncResponseTransformer;
import software.amazon.encryption.s3.S3EncryptionClientException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.CompletionHandler;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static software.amazon.awssdk.core.FileTransformerConfiguration.FileWriteOption.CREATE_OR_APPEND_TO_EXISTING;
import static software.amazon.awssdk.core.FileTransformerConfiguration.FileWriteOption.CREATE_OR_REPLACE_EXISTING;
import static software.amazon.awssdk.utils.FunctionalUtils.invokeSafely;

public class AsyncRequestBodySubscriber {

    private Subscription subscription;
    private ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    private Optional<Long> contentLength;
    private final Object lock = new Object();

    public byte[] getByteBuffer(AsyncRequestBody asyncRequestBody) {
        contentLength = asyncRequestBody.contentLength();
        if(asyncRequestBody instanceof ByteArrayAsyncRequestBody) {
            asyncRequestBody.subscribe(byteArraySubscriber);
        }
        else if(asyncRequestBody instanceof FileAsyncRequestBody) {
            // TODO: FileAsyncRequestBody Subscriber implementation
            asyncRequestBody.subscribe(fileSubscriber);
         }
        return outputStream.toByteArray();

    }

    private Subscriber<ByteBuffer> byteArraySubscriber = new Subscriber<ByteBuffer>() {
        @Override
        public void onSubscribe(Subscription s) {
            subscription = s;
            subscription.request(1);
        }

        @Override
        public void onNext(ByteBuffer b) {
            try {
                outputStream.write(b.array());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void onError(Throwable t) {
            throw new S3EncryptionClientException("" + t);
        }

        @Override
        public void onComplete() {
        }
    };

    public static byte[] trim(byte[] bytes) {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0) {
            --i;
        }

        return Arrays.copyOf(bytes, i + 1);
    }

    private boolean done = false;
    // TODO: FileAsyncRequestBody Subscriber implementation
    private Subscriber<ByteBuffer> fileSubscriber = new Subscriber<ByteBuffer>() {
        @Override
        public void onSubscribe(Subscription s) {
            subscription = s;
            synchronized (lock) {
                subscription.request(1);
            }
            try {
                subscription.wait(16);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void onNext(ByteBuffer b) {
            synchronized (lock) {
                subscription.request(1);
                try {
                    outputStream.write(trim(b.array()));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                done = true;
            }
            //notifyAll();
        }

        @Override
        public void onError(Throwable t) {
            throw new S3EncryptionClientException("" + t);
        }

        @Override
        public void onComplete() {
        }
    };


//    private final Subscriber<ByteBuffer> fileSubscriber1 = new Subscriber<ByteBuffer>() {
//        private final AtomicLong position = new AtomicLong(0);
//        private final AsynchronousFileChannel fileChannel = ;
//        private final Path path;
//        private final CompletableFuture<Void> future;
//        private final Consumer<Throwable> onErrorMethod;
//
//        private volatile boolean writeInProgress = false;
//        private volatile boolean closeOnLastWrite = false;
//        private Subscription subscription;
//
//        @Override
//        public void onSubscribe(Subscription s) {
//            if (this.subscription != null) {
//                s.cancel();
//                return;
//            }
//            this.subscription = s;
//            // Request the first chunk to start producing content
//            s.request(1);
//        }
//
//        @Override
//        public void onNext(ByteBuffer byteBuffer) {
//            if (byteBuffer == null) {
//                throw new NullPointerException("Element must not be null");
//            }
//
//            performWrite(byteBuffer);
//        }
//
//        private void performWrite(ByteBuffer byteBuffer) {
//            writeInProgress = true;
//
//            fileChannel.write(byteBuffer, position.get(), byteBuffer, new CompletionHandler<Integer, ByteBuffer>() {
//                @Override
//                public void completed(Integer result, ByteBuffer attachment) {
//                    position.addAndGet(result);
//
//                    if (byteBuffer.hasRemaining()) {
//                        performWrite(byteBuffer);
//                    } else {
//                        synchronized (fileSubscriber1.this) {
//                            writeInProgress = false;
//                            if (closeOnLastWrite) {
//                                close();
//                            } else {
//                                subscription.request(1);
//                            }
//                        }
//                    }
//                }
//
//                @Override
//                public void failed(Throwable exc, ByteBuffer attachment) {
//                    subscription.cancel();
//                    future.completeExceptionally(exc);
//                }
//            });
//        }
//
//        @Override
//        public void onError(Throwable t) {
//            onErrorMethod.accept(t);
//        }
//
//        @Override
//        public void onComplete() {
//            // if write in progress, tell write to close on finish.
//            synchronized (this) {
//                if (writeInProgress) {
//                    closeOnLastWrite = true;
//                } else {
//                    close();
//                }
//            }
//        }
//
//        private void close() {
//            try {
//                if (fileChannel != null) {
//                    invokeSafely(fileChannel::close);
//                }
//                future.complete(null);
//            } catch (RuntimeException exception) {
//                future.completeExceptionally(exception);
//            }
//        }
//
//        @Override
//        public String toString() {
//            return getClass() + ":" + path.toString();
//        }
//        private AsynchronousFileChannel createChannel(Path path) throws IOException {
//            switch (configuration.fileWriteOption()) {
//                case CREATE_OR_APPEND_TO_EXISTING:
//                    return AsynchronousFileChannel.open(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
//                case CREATE_OR_REPLACE_EXISTING:
//                    return AsynchronousFileChannel.open(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE,
//                            StandardOpenOption.TRUNCATE_EXISTING);
//                case CREATE_NEW:
//                    return AsynchronousFileChannel.open(path, StandardOpenOption.WRITE, CREATE_NEW);
//                default:
//                    throw new IllegalArgumentException("Unsupported file write option: " + configuration.fileWriteOption());
//            }
//        }
//
//    };

}
