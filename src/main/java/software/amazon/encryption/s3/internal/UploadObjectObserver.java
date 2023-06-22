// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import org.apache.commons.logging.LogFactory;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.SdkPartType;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

public class UploadObjectObserver {
    private final List<Future<Map<Integer, UploadPartResponse>>> futures = new ArrayList<>();
    private PutObjectRequest request;
    private String uploadId;
    private S3AsyncClient s3AsyncClient;
    private S3EncryptionClient s3EncryptionClient;
    private ExecutorService es;

    public UploadObjectObserver init(PutObjectRequest req,
                                     S3AsyncClient s3AsyncClient, S3EncryptionClient s3EncryptionClient, ExecutorService es) {
        this.request = req;
        this.s3AsyncClient = s3AsyncClient;
        this.s3EncryptionClient = s3EncryptionClient;
        this.es = es;
        return this;
    }

    protected CreateMultipartUploadRequest newCreateMultipartUploadRequest(
            PutObjectRequest request) {
        return CreateMultipartUploadRequest.builder()
                .bucket(request.bucket())
                .key(request.key())
                .metadata(request.metadata())
                .overrideConfiguration(request.overrideConfiguration().orElse(null))
                .build();
    }

    public String onUploadCreation(PutObjectRequest req) {
        CreateMultipartUploadResponse res =
                s3EncryptionClient.createMultipartUpload(newCreateMultipartUploadRequest(req));
        return this.uploadId = res.uploadId();
    }

    public void onPartCreate(PartCreationEvent event) {
        final File part = event.getPart();
        final UploadPartRequest reqUploadPart =
                newUploadPartRequest(event);
        final OnFileDelete fileDeleteObserver = event.getFileDeleteObserver();
        futures.add(es.submit(new Callable<Map<Integer, UploadPartResponse>>() {
            @Override
            public Map<Integer, UploadPartResponse> call() {
                // Upload the ciphertext directly via the non-encrypting
                // s3 client
                try {
                    AsyncRequestBody noRetriesBody = new NoRetriesAsyncRequestBody(AsyncRequestBody.fromFile(part));
                    return uploadPart(reqUploadPart, noRetriesBody);
                } catch (CompletionException e) {
                    // Unwrap completion exception
                    throw new S3EncryptionClientException(e.getCause().getMessage(), e.getCause());
                } finally {
                    // clean up part already uploaded
                    if (!part.delete()) {
                        LogFactory.getLog(getClass()).debug(
                                "Ignoring failure to delete file " + part
                                        + " which has already been uploaded");
                    } else {
                        if (fileDeleteObserver != null)
                            fileDeleteObserver.onFileDelete(null);
                    }
                }
            }
        }));
    }

    public CompleteMultipartUploadResponse onCompletion(List<CompletedPart> partETags) {
        return s3EncryptionClient.completeMultipartUpload(builder -> builder
                .bucket(request.bucket())
                .key(request.key())
                .uploadId(uploadId)
                .multipartUpload(partBuilder -> partBuilder.parts(partETags)));
    }

    public void onAbort() {
        for (Future<?> future : futures()) {
            future.cancel(true);
        }
        if (uploadId != null) {
            try {
                s3EncryptionClient.abortMultipartUpload(builder -> builder.bucket(request.bucket())
                        .key(request.key())
                        .uploadId(uploadId));
            } catch (Exception e) {
                LogFactory.getLog(getClass())
                        .debug("Failed to abort multi-part upload: " + uploadId, e);
            }
        }
    }

    protected UploadPartRequest newUploadPartRequest(PartCreationEvent event) {
        final SdkPartType partType;
        if (event.isLastPart()) {
            partType = SdkPartType.LAST;
        } else {
            partType = SdkPartType.DEFAULT;
        }
        return UploadPartRequest.builder()
                .bucket(request.bucket())
                .key(request.key())
                .partNumber(event.getPartNumber())
                .sdkPartType(partType)
                .uploadId(uploadId)
                .build();
    }

    protected Map<Integer, UploadPartResponse> uploadPart(UploadPartRequest reqUploadPart, AsyncRequestBody requestBody) {
        // Upload the ciphertext directly via the non-encrypting
        // s3 client
        return Collections.singletonMap(reqUploadPart.partNumber(), s3AsyncClient.uploadPart(reqUploadPart, requestBody).join());
    }

    public List<Future<Map<Integer, UploadPartResponse>>> futures() {
        return futures;
    }
}