package software.amazon.encryption.s3;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.utils.BoundedZerosInputStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
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
    public void multipartUploadV3() throws IOException {
        final String objectKey = "multipart-upload-v3";

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
        CreateMultipartUploadResponse createResponse = v3Client.createMultipartUpload(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));

        List<CompletedPart> partETags = new ArrayList<>();

        // Upload each part and store eTags in partETags
        for (int i = 1; i <= 11; i++) {
            // Create the request to upload a part.
            // Upload the part and add the response's eTag to our list.
            int finalI = i;
            UploadPartResponse uploadPartResponse = v3Client.uploadPart(builder -> builder
                    .bucket(BUCKET)
                    .key(objectKey)
                    .uploadId(createResponse.uploadId())
                    .partNumber(finalI)
                    .overrideConfiguration(isLastPart(finalI == 11)), RequestBody.fromInputStream(f[finalI - 1], fileSizeLimit));
            partETags.add(CompletedPart.builder()
                    .partNumber(i)
                    .eTag(uploadPartResponse.eTag())
                    .build());
        }

        // Complete the multipart upload.
        v3Client.completeMultipartUpload(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(createResponse.uploadId())
                .multipartUpload(partBuilder -> partBuilder.parts(partETags)));

        // Asserts
        ResponseBytes<GetObjectResponse> result = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));

        String inputAsString = IoUtils.toUtf8String(new BoundedZerosInputStream(fileSizeLimit * 11));
        String outputAsString = IoUtils.toUtf8String(result.asInputStream());
        assertEquals(inputAsString, outputAsString);

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }
}
