package software.amazon.encryption.s3;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.transfer.s3.S3TransferManager;
import software.amazon.awssdk.transfer.s3.model.CompletedDownload;
import software.amazon.awssdk.transfer.s3.model.Download;
import software.amazon.awssdk.transfer.s3.model.DownloadRequest;
import software.amazon.awssdk.transfer.s3.model.Upload;
import software.amazon.awssdk.transfer.s3.model.UploadRequest;
import software.amazon.awssdk.transfer.s3.progress.LoggingTransferListener;
import software.amazon.encryption.s3.utils.BoundedInputStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class TransferManagerTest {

    private static SecretKey AES_KEY;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();
    }

    @Test
    public void transferManagerUploadString() {
        final String objectKey = appendTestSuffix("tm-string");
        final String input = "short test of s3 encryption client with transfer manager";
        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        S3TransferManager transferManager =
                S3TransferManager.builder()
                        .s3Client(v3AsyncClient)
                        .build();

        Upload upload = transferManager.upload(UploadRequest.builder()
                .putObjectRequest((builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build()))
                .requestBody(AsyncRequestBody.fromString(input))
                .build());
        upload.completionFuture().join();

        // tm download
        Download<ResponseBytes<GetObjectResponse>> download = transferManager.download(DownloadRequest.builder()
                .getObjectRequest(GetObjectRequest.builder()
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build())
                .responseTransformer(AsyncResponseTransformer.toBytes())
                .build());
        CompletedDownload<ResponseBytes<GetObjectResponse>> resp = download.completionFuture().join();
        assertEquals(input, resp.result().asUtf8String());

        // Cleanup
        deleteObject(BUCKET, objectKey, v3AsyncClient);
        transferManager.close();
    }

    @Test
    public void transferManagerUploadStream() throws IOException {
        final String objectKey = appendTestSuffix("tm-stream");

        final long fileSizeLimit = 1024 * 1024 * 100;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
        final InputStream objectStreamForResultTm = new BoundedInputStream(fileSizeLimit);

        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableDelayedAuthenticationMode(true)
                .enableMultipartPutObject(true)
                .build();
        S3TransferManager transferManager =
                S3TransferManager.builder()
                        .s3Client(v3AsyncClient)
                        .build();

        ExecutorService singleThreadExecutor = Executors.newSingleThreadExecutor();
        Upload upload = transferManager.upload(UploadRequest.builder()
                .putObjectRequest((builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build()))
                .requestBody(AsyncRequestBody.fromInputStream(inputStream, fileSizeLimit, singleThreadExecutor))
                .addTransferListener(LoggingTransferListener.create())
                .build());
        upload.completionFuture().join();
        singleThreadExecutor.shutdown();

        // tm download
        Download<ResponseInputStream<GetObjectResponse>> download = transferManager.download(DownloadRequest.builder()
                .getObjectRequest(GetObjectRequest.builder()
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build())
                .responseTransformer(AsyncResponseTransformer.toBlockingInputStream())
                .build());

        CompletedDownload<ResponseInputStream<GetObjectResponse>> resp = download.completionFuture().join();
        assertTrue(IOUtils.contentEquals(objectStreamForResultTm, resp.result()));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3AsyncClient);
        transferManager.close();
    }

    @Test
    public void transferManagerUploadStreamCrt() throws ExecutionException, InterruptedException, IOException {
        final String objectKey = appendTestSuffix("tm-stream-crt");

        final long fileSizeLimit = 1024 * 1024 * 100;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
        final InputStream objectStreamForResultTm = new BoundedInputStream(fileSizeLimit);

        S3AsyncClient wrappedCrt = S3AsyncClient.crtBuilder()
                .build();
        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .wrappedClient(wrappedCrt)
                .aesKey(AES_KEY)
                .enableDelayedAuthenticationMode(true)
                .enableMultipartPutObject(true)
                .build();
        S3TransferManager transferManager =
                S3TransferManager.builder()
                        .s3Client(v3AsyncClient)
                        .build();

        ExecutorService singleThreadExecutor = Executors.newSingleThreadExecutor();
        Upload upload = transferManager.upload(UploadRequest.builder()
                .putObjectRequest((builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build()))
                .requestBody(AsyncRequestBody.fromInputStream(inputStream, fileSizeLimit, singleThreadExecutor))
                .addTransferListener(LoggingTransferListener.create())
                .build());
        upload.completionFuture().join();
        singleThreadExecutor.shutdown();

        Download<ResponseInputStream<GetObjectResponse>> download = transferManager.download(DownloadRequest.builder()
                .getObjectRequest(GetObjectRequest.builder()
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build())
                .responseTransformer(AsyncResponseTransformer.toBlockingInputStream())
                .build());
        download.completionFuture().join();
        CompletedDownload<ResponseInputStream<GetObjectResponse>> resp = download.completionFuture().get();

        assertTrue(IOUtils.contentEquals(objectStreamForResultTm, resp.result()));
        deleteObject(BUCKET, objectKey, v3AsyncClient);
        transferManager.close();
    }

}
