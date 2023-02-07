package software.amazon.encryption.s3;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.materials.MultipartConfiguration;
import software.amazon.encryption.s3.utils.BoundedZerosInputStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.S3EncryptionClient.isLastPart;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;

public class S3EncryptionClientMultipartUploadTest {
    private static SecretKey AES_KEY;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();
    }

    @Test
    public void multipartPutObject() throws IOException {
        final String objectKey = appendTestSuffix("multipart-put-object");

        final long fileSizeLimit = 1024 * 1024 * 500;
        final InputStream inputStream = new BoundedZerosInputStream(fileSizeLimit);
        final InputStream objectStreamForResult = new BoundedZerosInputStream(fileSizeLimit);

        Security.addProvider(new BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");

        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableMultipartPutObject(true)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(provider)
                .build();

        MultipartConfiguration configuration = MultipartConfiguration.builder()
                .maxConnections(30)
                .build();

        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext, configuration))
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

    //@Test
    public void multipartUploadV3OutputStream() throws IOException {
        final String objectKey = appendTestSuffix("multipart-upload-v3-output-stream");

        // Overall "file" is 100MB, split into 10MB parts
        final long fileSizeLimit = 1024 * 1024 * 100;
        final int PART_SIZE = 10 * 1024 * 1024;
        final InputStream inputStream = new BoundedZerosInputStream(fileSizeLimit);

        Security.addProvider(new BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableDelayedAuthenticationMode(true)
                .cryptoProvider(provider)
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
                    .overrideConfiguration(isLastPart(false))
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

        // Last Part
        UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .partNumber(partsSent)
                .overrideConfiguration(isLastPart(true))
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
        ResponseBytes<GetObjectResponse> result = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));

        String inputAsString = IoUtils.toUtf8String(new BoundedZerosInputStream(fileSizeLimit));
        String outputAsString = IoUtils.toUtf8String(result.asInputStream());
        assertEquals(inputAsString, outputAsString);

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }
}
