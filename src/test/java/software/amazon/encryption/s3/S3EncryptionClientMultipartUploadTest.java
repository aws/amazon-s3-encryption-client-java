package software.amazon.encryption.s3;

import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.CompleteMultipartUploadRequest;
import com.amazonaws.services.s3.model.CompleteMultipartUploadResult;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.InitiateMultipartUploadRequest;
import com.amazonaws.services.s3.model.InitiateMultipartUploadResult;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.PartETag;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.UploadPartResult;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.SdkPartType;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.utils.BoundedInputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class S3EncryptionClientMultipartUploadTest {
    private static Provider PROVIDER;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        PROVIDER = Security.getProvider("BC");
    }

    @Test
    public void multipartPutObjectAsync() throws IOException {
        final String objectKey = appendTestSuffix("multipart-put-object-async");

        final long fileSizeLimit = 1024 * 1024 * 100;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
        final InputStream objectStreamForResult = new BoundedInputStream(fileSizeLimit);

        S3AsyncClient v3Client = S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableMultipartPutObject(true)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(PROVIDER)
                .build();

        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        CompletableFuture<PutObjectResponse> futurePut = v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
                .key(objectKey), AsyncRequestBody.fromInputStream(inputStream, fileSizeLimit, Executors.newSingleThreadExecutor()));
        futurePut.join();

        // Asserts
        CompletableFuture<ResponseInputStream<GetObjectResponse>> getFuture = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(S3EncryptionClient.withAdditionalConfiguration(encryptionContext))
                .key(objectKey), AsyncResponseTransformer.toBlockingInputStream());
        ResponseInputStream<GetObjectResponse> output = getFuture.join();

        assertTrue(IOUtils.contentEquals(objectStreamForResult, output));

        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }


    @Test
    public void multipartPutObject() throws IOException {
        final String objectKey = appendTestSuffix("multipart-put-object");

        final long fileSizeLimit = 1024 * 1024 * 100;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
        final InputStream objectStreamForResult = new BoundedInputStream(fileSizeLimit);

        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableMultipartPutObject(true)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(PROVIDER)
                .build();

        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
                .key(objectKey), RequestBody.fromInputStream(inputStream, fileSizeLimit));

        // Asserts
        ResponseInputStream<GetObjectResponse> output = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(S3EncryptionClient.withAdditionalConfiguration(encryptionContext))
                .key(objectKey));

        assertTrue(IOUtils.contentEquals(objectStreamForResult, output));

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }

    @RepeatedTest(10)
    public void multipartUploadV3OutputStream() throws IOException {
        final String objectKey = appendTestSuffix("multipart-upload-v3-output-stream");

        // Overall "file" is 100MB, split into 10MB parts
        final long fileSizeLimit = 1024 * 1024 * 100;
        final int PART_SIZE = 10 * 1024 * 1024;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(PROVIDER)
                .build();

        // Create Multipart upload request to S3
        CreateMultipartUploadResponse initiateResult = v3Client.createMultipartUpload(builder ->
                builder.bucket(BUCKET).key(objectKey));

        List<CompletedPart> partETags = new ArrayList<>();

        int bytesRead, bytesSent = 0;
        // 10MB parts
        byte[] partData = new byte[PART_SIZE];
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int partsSent = 1;

        while ((bytesRead = inputStream.read(partData, 0, partData.length)) != -1) {
            outputStream.write(partData, 0, bytesRead);
            if (bytesSent < PART_SIZE) {
                bytesSent += bytesRead;
                continue;
            }

            UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                    .bucket(BUCKET)
                    .key(objectKey)
                    .uploadId(initiateResult.uploadId())
                    .partNumber(partsSent)
                    .build();

            final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
            UploadPartResponse uploadPartResult = v3Client.uploadPart(uploadPartRequest,
                    RequestBody.fromInputStream(partInputStream, partInputStream.available()));
            partETags.add(CompletedPart.builder()
                    .partNumber(partsSent)
                    .eTag(uploadPartResult.eTag())
                    .build());
            outputStream.reset();
            bytesSent = 0;
            partsSent++;
        }
        inputStream.close();

        // Last Part
        UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .partNumber(partsSent)
                .sdkPartType(SdkPartType.LAST)
                .build();

        final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
        UploadPartResponse uploadPartResult = v3Client.uploadPart(uploadPartRequest,
                RequestBody.fromInputStream(partInputStream, partInputStream.available()));
        partETags.add(CompletedPart.builder()
                .partNumber(partsSent)
                .eTag(uploadPartResult.eTag())
                .build());

        // Complete the multipart upload.
        v3Client.completeMultipartUpload(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .multipartUpload(partBuilder -> partBuilder.parts(partETags)));

        // Asserts
        InputStream resultStream = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)).asInputStream();

        assertTrue(IOUtils.contentEquals(new BoundedInputStream(fileSizeLimit), resultStream));
        resultStream.close();

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }

    @RepeatedTest(20)
    public void multipartUploadV3OutputStreamPartSize() throws IOException {
        final String objectKey = appendTestSuffix("multipart-upload-v3-output-stream-part-size");

        // Overall "file" is 30MB, split into 10MB parts
        final long fileSizeLimit = 1024 * 1024 * 35;
        System.out.println(String.format("  TEST: Upload obj with %d total bytes", fileSizeLimit));
        final int PART_SIZE = 10 * 1024 * 1024;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(PROVIDER)
                .build();

        // Create Multipart upload request to S3
        CreateMultipartUploadResponse initiateResult = v3Client.createMultipartUpload(builder ->
                builder.bucket(BUCKET).key(objectKey));

        List<CompletedPart> partETags = new ArrayList<>();

        int bytesRead, bytesSent = 0;
        // 10MB parts
        byte[] partData = new byte[PART_SIZE];
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int partsSent = 1;

        while ((bytesRead = inputStream.read(partData, 0, partData.length)) != -1) {
            outputStream.write(partData, 0, bytesRead);
            if (bytesSent < PART_SIZE) {
                bytesSent += bytesRead;
                continue;
            }

            final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
            UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                    .bucket(BUCKET)
                    .key(objectKey)
                    .uploadId(initiateResult.uploadId())
                    .partNumber(partsSent)
                    .contentLength((long) partInputStream.available())
                    .build();

            System.out.println(String.format("  TEST: available bytes: %d", (long) partInputStream.available()));
            System.out.println(String.format("  TEST: Upload part no. %d with %d bytes", partsSent, uploadPartRequest.contentLength()));
            UploadPartResponse uploadPartResult = v3Client.uploadPart(uploadPartRequest,
                    RequestBody.fromInputStream(partInputStream, partInputStream.available()));
            partETags.add(CompletedPart.builder()
                    .partNumber(partsSent)
                    .eTag(uploadPartResult.eTag())
                    .build());
            outputStream.reset();
            bytesSent = 0;
            partsSent++;
        }

        final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());

        // Last Part
        UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .partNumber(partsSent)
                .contentLength((long) partInputStream.available())
                .sdkPartType(SdkPartType.LAST)
                .build();

        System.out.println(String.format("  TEST: upload (last) part no. %d with %d bytes", partsSent,
                uploadPartRequest.contentLength()));
        UploadPartResponse uploadPartResult = v3Client.uploadPart(uploadPartRequest,
                RequestBody.fromInputStream(partInputStream, partInputStream.available()));
        partETags.add(CompletedPart.builder()
                .partNumber(partsSent)
                .eTag(uploadPartResult.eTag())
                .build());

        // Complete the multipart upload.
        CompleteMultipartUploadResponse completeMultipartUploadResponse = v3Client.completeMultipartUpload(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .multipartUpload(partBuilder -> partBuilder.parts(partETags)));

        System.out.println("complete: " + completeMultipartUploadResponse.eTag());
        // Asserts
        ResponseBytes<GetObjectResponse> result = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));

        String inputAsString = IoUtils.toUtf8String(new BoundedInputStream(fileSizeLimit));
        String outputAsString = IoUtils.toUtf8String(result.asInputStream());
        assertEquals(inputAsString, outputAsString);

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }

    @RepeatedTest(20)
    public void multipartUploadV2OutputStreamPartSize() throws IOException {
        final String objectKey = appendTestSuffix("multipart-upload-v2-output-stream-part-size");

        // Overall "file" is 35MB, split into 10MB parts
        final long fileSizeLimit = 1024 * 1024 * 35;
        System.out.println(String.format("  TEST: Upload obj with %d total bytes", fileSizeLimit));
        final int PART_SIZE = 10 * 1024 * 1024;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);

        // V2 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // Create Multipart upload request to S3
        InitiateMultipartUploadResult initiateResult = v2Client.initiateMultipartUpload(new InitiateMultipartUploadRequest(BUCKET, objectKey));

        List<PartETag> partETags = new ArrayList<>();

        int bytesRead, bytesSent = 0;
        // 10MB parts
        byte[] partData = new byte[PART_SIZE];
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int partsSent = 1;

        while ((bytesRead = inputStream.read(partData, 0, partData.length)) != -1) {
            outputStream.write(partData, 0, bytesRead);
            if (bytesSent < PART_SIZE) {
                bytesSent += bytesRead;
                continue;
            }

            final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
            com.amazonaws.services.s3.model.UploadPartRequest uploadPartRequest = new com.amazonaws.services.s3.model.UploadPartRequest();
            uploadPartRequest.setPartSize(partInputStream.available());
            uploadPartRequest.setBucketName(BUCKET);
            uploadPartRequest.setKey(objectKey);
            uploadPartRequest.setUploadId(initiateResult.getUploadId());
            uploadPartRequest.setPartNumber(partsSent);
            uploadPartRequest.setInputStream(partInputStream);

            System.out.println(String.format("  TEST: available bytes: %d", (long) partInputStream.available()));
            System.out.println(String.format("  TEST: Upload part no. %d with %d bytes", partsSent, uploadPartRequest.getPartSize()));
            UploadPartResult uploadPartResult = v2Client.uploadPart(uploadPartRequest);
            partETags.add(uploadPartResult.getPartETag());
            outputStream.reset();
            bytesSent = 0;
            partsSent++;
        }

        final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());

        // Last Part
        com.amazonaws.services.s3.model.UploadPartRequest uploadPartRequest = new com.amazonaws.services.s3.model.UploadPartRequest();
        uploadPartRequest.setBucketName(BUCKET);
        uploadPartRequest.setKey(objectKey);
        uploadPartRequest.setUploadId(initiateResult.getUploadId());
        uploadPartRequest.setPartNumber(partsSent);
        uploadPartRequest.setPartSize(partInputStream.available());
        uploadPartRequest.setLastPart(true);
        uploadPartRequest.setInputStream(partInputStream);

        System.out.println(String.format("  TEST: upload (last) part no. %d with %d bytes", partsSent, uploadPartRequest.getPartSize()));

        UploadPartResult uploadPartResult = v2Client.uploadPart(uploadPartRequest);

        partETags.add(uploadPartResult.getPartETag());

        // Complete the multipart upload.
        CompleteMultipartUploadRequest completeMultipartUploadRequest = new CompleteMultipartUploadRequest(BUCKET,
                objectKey, initiateResult.getUploadId(), partETags);
        CompleteMultipartUploadResult completeMultipartUploadResult = v2Client.completeMultipartUpload(completeMultipartUploadRequest);

        System.out.println("complete: " + completeMultipartUploadResult.getETag());

        // Asserts
        S3Object result = v2Client.getObject(BUCKET, objectKey);

        String inputAsString = IoUtils.toUtf8String(new BoundedInputStream(fileSizeLimit));
        String outputAsString = IoUtils.toUtf8String(result.getObjectContent());
        assertEquals(inputAsString, outputAsString);
    }

    @Test
    public void multipartUploadV3OutputStreamPartSizeMismatch() throws IOException {
        final String objectKey = appendTestSuffix("multipart-upload-v3-output-stream-part-size-mismatch");

        // Overall "file" is 30MB, split into 10MB parts
        final long fileSizeLimit = 1024 * 1024 * 30;
        final int PART_SIZE = 10 * 1024 * 1024;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(PROVIDER)
                .build();

        // Create Multipart upload request to S3
        CreateMultipartUploadResponse initiateResult = v3Client.createMultipartUpload(builder ->
                builder.bucket(BUCKET).key(objectKey));

        int bytesRead, bytesSent = 0;
        // 10MB parts
        byte[] partData = new byte[PART_SIZE];
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int partsSent = 1;

        while ((bytesRead = inputStream.read(partData, 0, partData.length)) != -1) {
            outputStream.write(partData, 0, bytesRead);
            if (bytesSent < PART_SIZE) {
                bytesSent += bytesRead;
                continue;
            }

            final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
            UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                    .bucket(BUCKET)
                    .key(objectKey)
                    .uploadId(initiateResult.uploadId())
                    .partNumber(partsSent)
                    .contentLength((long) partInputStream.available() + 1) // mismatch
                    .build();

            assertThrows(S3EncryptionClientException.class, () -> v3Client.uploadPart(uploadPartRequest,
                    RequestBody.fromInputStream(partInputStream, partInputStream.available())));
        }

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }

}
