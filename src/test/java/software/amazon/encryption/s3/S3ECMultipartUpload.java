package software.amazon.encryption.s3;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.encryption.s3.utils.BoundedZerosInputStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.encryption.s3.S3EncryptionClient.isLastPart;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalEncryptionContext;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;


/**
 * This class is an integration test for verifying compatibility of ciphertexts
 * between V1, V2, and V3 clients under various conditions.
 */
public class S3ECMultipartUpload {
    private static SecretKey AES_KEY;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();
    }

    @Test
    public void multipartUploadV3() throws IOException {
        final String objectKey = "multipart-Upload-v3";

        final long fileSizeLimit = 1024 * 1024 * 10;
        InputStream[] f = new InputStream[11];
        for (int i = 0; i < 11; i++) {
            f[i] = new BoundedZerosInputStream(fileSizeLimit);
        }
        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableDelayedAuthenticationMode(true)
                .build();

        // Create Multipart upload request to S3
        CreateMultipartUploadRequest create = CreateMultipartUploadRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build();
        CreateMultipartUploadResponse createResponse = v3Client.createMultipartUpload(create);

        List<CompletedPart> partETags = new ArrayList<>();

        // Upload each part and store eTags in partETags
        for (int i = 1; i <= 10; i++) {
            // Create the request to upload a part.
            UploadPartRequest uploadRequest = UploadPartRequest.builder()
                    .bucket(BUCKET)
                    .key(objectKey)
                    .uploadId(createResponse.uploadId())
                    .overrideConfiguration(AwsRequestOverrideConfiguration.builder().build())
                    .partNumber(i)
                    .build();
            // Upload the part and add the response's eTag to our list.
            UploadPartResponse uploadPartResponse = v3Client.uploadPart(uploadRequest,
                    RequestBody.fromInputStream(f[i - 1], fileSizeLimit));
            partETags.add(CompletedPart.builder()
                    .partNumber(i)
                    .eTag(uploadPartResponse.eTag())
                    .build());
        }
        UploadPartRequest uploadRequest = UploadPartRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(createResponse.uploadId())
                .partNumber(11)
                .overrideConfiguration(isLastPart(true))
                .build();
        // Upload the last part and add the response's ETag to our list.
        UploadPartResponse uploadPartResponse = v3Client.uploadPart(uploadRequest, RequestBody.fromInputStream(f[10], fileSizeLimit));
        partETags.add(CompletedPart.builder()
                .partNumber(11)
                .eTag(uploadPartResponse.eTag())
                .build());
        // Complete the multipart upload.
        CompleteMultipartUploadRequest compRequest = CompleteMultipartUploadRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(createResponse.uploadId())
                .multipartUpload(builder -> builder.parts(partETags))
                .build();
        v3Client.completeMultipartUpload(compRequest);

        // Asserts
        ResponseBytes<GetObjectResponse> result = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));

        assertEquals(Arrays.toString(new BoundedZerosInputStream(fileSizeLimit * 11).readAllBytes()),
                Arrays.toString(result.asInputStream().readAllBytes()));

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }

    @Test
    public void multipartUploadV3withEncryptionContext() throws IOException {
        final String objectKey = "multipart-upload-v3-with-encryption-context";

        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        final long fileSizeLimit = 1024 * 1024 * 10;
        InputStream[] f = new InputStream[11];
        for (int i = 0; i < 11; i++) {
            f[i] = new BoundedZerosInputStream(fileSizeLimit);
        }
        // V3 Client
        S3EncryptionClient v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableDelayedAuthenticationMode(true)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Create Multipart upload request to S3
        CreateMultipartUploadRequest create = CreateMultipartUploadRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalEncryptionContext(encryptionContext))
                .build();
        CreateMultipartUploadResponse createResponse = v3Client.createMultipartUpload(create);

        List<CompletedPart> partETags = new ArrayList<>();

        for (int i = 1; i <= 10; i++) {
            // Create the request to upload a part.
            UploadPartRequest uploadRequest = UploadPartRequest.builder()
                    .bucket(BUCKET)
                    .key(objectKey)
                    .uploadId(createResponse.uploadId())
                    .partNumber(i)
                    .build();
            // Upload the part and add the response's ETag to our list.
            UploadPartResponse uploadPartResponse = v3Client.uploadPart(uploadRequest, RequestBody.fromInputStream(f[i - 1], fileSizeLimit));
            partETags.add(CompletedPart.builder()
                    .partNumber(i)
                    .eTag(uploadPartResponse.eTag())
                    .build());
        }
        UploadPartRequest uploadRequest = UploadPartRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(createResponse.uploadId())
                .partNumber(11)
                .build();
        // Upload the last part and add the response's ETag to our list.
        UploadPartResponse uploadPartResponse = v3Client.uploadPart(uploadRequest, RequestBody.fromInputStream(f[10], fileSizeLimit));
        partETags.add(CompletedPart.builder()
                .partNumber(11)
                .eTag(uploadPartResponse.eTag())
                .build());

        // Complete the multipart upload.
        CompleteMultipartUploadRequest compRequest = CompleteMultipartUploadRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(createResponse.uploadId())
                .multipartUpload(builder -> builder.parts(partETags))
                .build();
        v3Client.completeMultipartUpload(compRequest);

        // Asserts
        ResponseBytes<GetObjectResponse> result = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalEncryptionContext(encryptionContext)));

        assertEquals(Arrays.toString(new BoundedZerosInputStream(fileSizeLimit * 11).readAllBytes()),
                Arrays.toString(result.asInputStream().readAllBytes()));

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }
}
