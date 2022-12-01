package software.amazon.encryption.s3;

import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.CompleteMultipartUploadRequest;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.InitiateMultipartUploadRequest;
import com.amazonaws.services.s3.model.InitiateMultipartUploadResult;
import com.amazonaws.services.s3.model.PartETag;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.UploadPartResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.utils.BoundedOnesInputStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.encryption.s3.S3EncryptionClient.isLastPart;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;

public class S3EncryptionClientMultipartUploadTest {
    private static SecretKey AES_KEY;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();
    }

    @Test
    public void multipartUploadV3OutputStream() throws IOException {
        final Date start = new Date();
        final String objectKey = "multipart-upload-v3-output-stream";

        // Overall "file" is 60MB, split into 10MB parts
        final long fileSizeLimit = 1024 * 1024 * 60;
        final int PART_SIZE = 10 * 1024 * 1024;
        final InputStream inputStream = new BoundedOnesInputStream(fileSizeLimit);

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableDelayedAuthenticationMode(true)
                .build();

        // Create Multipart upload request to S3
        System.out.printf("Starting multipart upload request: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
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
                    .overrideConfiguration(isLastPart(false))
                    .build();

            final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
            System.out.printf("Making an upload part request: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
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

        // Last Part
        UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .partNumber(partsSent)
                .overrideConfiguration(isLastPart(true))
                .build();

        final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
        System.out.printf("Last part upload request: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
        UploadPartResponse uploadPartResult = v3Client.uploadPart(uploadPartRequest,
                RequestBody.fromInputStream(partInputStream, partInputStream.available()));
        partETags.add(CompletedPart.builder()
                .partNumber(partsSent)
                .eTag(uploadPartResult.eTag())
                .build());

        // Complete the multipart upload.
        System.out.printf("Completing multipart upload request: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
        v3Client.completeMultipartUpload(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .multipartUpload(partBuilder -> partBuilder.parts(partETags)));

        // Asserts
        System.out.printf("Now getting result: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
        ResponseBytes<GetObjectResponse> result = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));

        String inputAsString = IoUtils.toUtf8String(new BoundedOnesInputStream(fileSizeLimit));
        System.out.printf("Got result: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
        String outputAsString = IoUtils.toUtf8String(result.asInputStream());
        System.out.printf("Asserting..: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
        assertEquals(inputAsString, outputAsString);

        System.out.printf("Deleting..: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
        System.out.printf("Done: %f\n", ((new Date()).getTime() - start.getTime()) / 1000.0);
    }

    @Test
    public void multipartUploadV2OutputStream() throws IOException {
        final String objectKey = "multipart-upload-v2-output-stream";
        final Date start = new Date();

        // Overall "file" is 60MB, split into 10MB parts
        final long fileSizeLimit = 1024 * 1024 * 60;
        final int PART_SIZE = 10 * 1024 * 1024;
        final InputStream inputStream = new BoundedOnesInputStream(fileSizeLimit);

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider).build();

        // Create Multipart upload request to S3
        System.out.printf("starting multipart upload request: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
        InitiateMultipartUploadRequest request = new InitiateMultipartUploadRequest(BUCKET, objectKey);
        InitiateMultipartUploadResult initiateResult = v2Client.initiateMultipartUpload(request);

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

            System.out.printf("making an upload part request: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
            com.amazonaws.services.s3.model.UploadPartRequest uploadPartRequest = new com.amazonaws.services.s3.model.UploadPartRequest();
            uploadPartRequest.setBucketName(BUCKET);
            uploadPartRequest.setKey(objectKey);
            uploadPartRequest.setUploadId(initiateResult.getUploadId());
            uploadPartRequest.setPartNumber(partsSent);
            uploadPartRequest.setLastPart(false);
            final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
            uploadPartRequest.setInputStream(partInputStream);
            uploadPartRequest.setPartSize(partInputStream.available());
            UploadPartResult uploadPartResult = v2Client.uploadPart(uploadPartRequest);
            partETags.add(uploadPartResult.getPartETag());
            outputStream.reset();
            bytesSent = 0;
            partsSent++;
        }

        // Last Part
        System.out.printf("last part upload request: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
        com.amazonaws.services.s3.model.UploadPartRequest uploadPartRequest = new com.amazonaws.services.s3.model.UploadPartRequest();
        uploadPartRequest.setBucketName(BUCKET);
        uploadPartRequest.setKey(objectKey);
        uploadPartRequest.setUploadId(initiateResult.getUploadId());
        uploadPartRequest.setPartNumber(partsSent);
        uploadPartRequest.setLastPart(true);
        final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
        uploadPartRequest.setInputStream(partInputStream);
        uploadPartRequest.setPartSize(partInputStream.available());
        UploadPartResult uploadPartResult = v2Client.uploadPart(uploadPartRequest);
        partETags.add(uploadPartResult.getPartETag());

        // Complete the multipart upload.
        System.out.printf("completing multipart upload request: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
        CompleteMultipartUploadRequest completeReq = new com.amazonaws.services.s3.model.CompleteMultipartUploadRequest(BUCKET, objectKey, initiateResult.getUploadId(), partETags);
        v2Client.completeMultipartUpload(completeReq);
        System.out.printf("now getting result: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
        final String result = v2Client.getObjectAsString(BUCKET, objectKey);
        System.out.printf("got result: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);

        String inputAsString = IoUtils.toUtf8String(new BoundedOnesInputStream(fileSizeLimit));
        System.out.printf("asserting..: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
        assertEquals(inputAsString, result);

        System.out.printf("deleting..: %d\n", ((new Date()).getTime() - start.getTime()) / 1000);
        v2Client.deleteObject(BUCKET, objectKey);
        System.out.printf("done: %f\n", ((new Date()).getTime() - start.getTime()) / 1000.0);
    }

}
