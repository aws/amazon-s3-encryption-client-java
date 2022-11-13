package software.amazon.encryption.s3;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.*;
import com.amazonaws.services.s3.model.DeleteObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.encryption.s3.utils.BoundedZerosInputStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * This class is an integration test for verifying compatibility of ciphertexts
 * between V1, V2, and V3 clients under various conditions.
 */
public class S3ECMultipartUpload {

    private static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");
    private static final String KMS_KEY_ID = System.getenv("AWS_S3EC_TEST_KMS_KEY_ID");
    private static final Region KMS_REGION = Region.getRegion(Regions.fromName(System.getenv("AWS_REGION")));

    private static SecretKey AES_KEY;
    private static KeyPair RSA_KEY_PAIR;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        RSA_KEY_PAIR = keyPairGen.generateKeyPair();
    }

    @Test
    public void multipartUploadV2() throws IOException {
        final String objectKey = "multipartUploadV2";

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        final long fileSizeLimit = 1024 * 1024 * 20;
        InputStream[] f = new InputStream[11];
        for (int i = 0; i<11; i++) {
            f[i] = new BoundedZerosInputStream(fileSizeLimit);
        }


        com.amazonaws.services.s3.model.InitiateMultipartUploadRequest initiate = new com.amazonaws.services.s3.model.InitiateMultipartUploadRequest(BUCKET,objectKey);
        com.amazonaws.services.s3.model.InitiateMultipartUploadResult initiateResult = v2Client.initiateMultipartUpload(initiate);
        List<PartETag> partETags = new ArrayList<PartETag>();

        for (int i = 1; i <= 11 ; i++) {
            // Create the request to upload a part.
            com.amazonaws.services.s3.model.UploadPartRequest uploadRequest = new com.amazonaws.services.s3.model.UploadPartRequest()
                    .withBucketName(BUCKET)
                    .withKey(objectKey)
                    .withInputStream(f[i-1])
                    .withUploadId(initiateResult.getUploadId())
                    .withPartNumber(i)
                    .withLastPart(i == 11);

            // Upload the part and add the response's ETag to our list.
            UploadPartResult uploadResult = v2Client.uploadPart(uploadRequest);
            partETags.add(uploadResult.getPartETag());
        }
        // Complete the multipart upload.
        com.amazonaws.services.s3.model.CompleteMultipartUploadRequest compRequest = new com.amazonaws.services.s3.model.CompleteMultipartUploadRequest(BUCKET, objectKey,
                initiateResult.getUploadId(), partETags);
        v2Client.completeMultipartUpload(compRequest);

        S3Object result = v2Client.getObject(BUCKET, objectKey);
        S3ObjectInputStream output = result.getObjectContent();
        // TODO: Need to check Actual and Expected Input Streams
        assertEquals((new BoundedZerosInputStream(fileSizeLimit * 11).read()),(result.getObjectContent().read()));

        v2Client.deleteObject(new DeleteObjectRequest(BUCKET, objectKey));
    }

    @Test
    public void multipartUploadV3() throws IOException {
        final String objectKey = "multipartUploadV3";

        CreateMultipartUploadRequest create = CreateMultipartUploadRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build();

        final long fileSizeLimit = 1024 * 1024 * 10;
        InputStream[] f = new InputStream[11];
        for (int i = 0; i<11; i++) {
            f[i] = new BoundedZerosInputStream(fileSizeLimit);
        }
        // V3 Client
        S3EncryptionClient v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableDelayedAuthenticationMode(true)
                .build();
        CreateMultipartUploadResponse createResponse = v3Client.createMultipartUpload(create);

        List<CompletedPart> partETags = new ArrayList<>();

        for (int i = 1; i <= 10 ; i++) {
            // Create the request to upload a part.
            UploadPartRequest uploadRequest = UploadPartRequest.builder()
                    .bucket(BUCKET)
                    .key(objectKey)
                    .uploadId(createResponse.uploadId())
                    .partNumber(i)
                    .build();
            // Upload the part and add the response's ETag to our list.
            UploadPartResponse uploadPartResponse = v3Client.uploadPart(uploadRequest, RequestBody.fromInputStream(f[i-1], fileSizeLimit));
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
        // Upload the part and add the response's ETag to our list.
        UploadPartResponse uploadPartResponse = v3Client.uploadLastPart(uploadRequest, RequestBody.fromInputStream(f[10], fileSizeLimit));
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

        ResponseBytes<GetObjectResponse> result = v3Client.getObjectAsBytes(builder -> builder.bucket(BUCKET).key(objectKey));
        // TODO: Need to check Actual and Expected Input Streams
        assertEquals((new BoundedZerosInputStream(fileSizeLimit * 11).read()),(result.asInputStream().read()));

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }
}
