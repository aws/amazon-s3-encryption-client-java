// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import org.reactivestreams.Subscriber;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.encryption.s3.S3EncryptionClientException;

import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * AsyncRequestBody which blocks re-subscription.
 * This is useful when retrying is problematic,
 * such as when uploading parts of a multipart upload.
 */
public class NoRetriesAsyncRequestBody implements AsyncRequestBody {

    private final AsyncRequestBody wrappedAsyncRequestBody;
    private final AtomicBoolean subscribeCalled = new AtomicBoolean(false);

    public NoRetriesAsyncRequestBody(final AsyncRequestBody wrappedAsyncRequestBody) {
        this.wrappedAsyncRequestBody = wrappedAsyncRequestBody;
    }

    @Override
    public Optional<Long> contentLength() {
        return wrappedAsyncRequestBody.contentLength();
    }

    @Override
    public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
        if (subscribeCalled.compareAndSet(false, true)) {
            wrappedAsyncRequestBody.subscribe(subscriber);
        } else {
            throw new S3EncryptionClientException("Re-subscription is not supported! Retry the entire operation.");
        }
    }
}
