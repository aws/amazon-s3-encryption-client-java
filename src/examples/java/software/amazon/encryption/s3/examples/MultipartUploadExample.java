package software.amazon.encryption.s3.examples;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.SdkPartType;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.utils.BoundedInputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;

public class MultipartUploadExample {
    public static String BUCKET;
    public static void main(final String[] args) throws IOException {
        BUCKET = args[0];
        LowLevelMultipartUpload();
        HighLevelMultipartPutObject();
    }

    /**
     * This example demonstrates a low-level approach to performing a multipart upload to an Amazon S3 bucket
     * using the S3 Client, performing encryption and decryption operations using the AWS Key Management Service (KMS).
     * It showcases the process of uploading a large object in smaller parts, processing and encrypting each part,
     * and then completing the multipart upload.
     *
     * @throws IOException If an I/O error occurs while reading or writing data.
     */
    public static void LowLevelMultipartUpload() throws IOException {
        final String objectKey = appendTestSuffix("low-level-multipart-upload-example");

        // Overall "file" is 100MB, split into 10MB parts
        final long fileSizeLimit = 1024 * 1024 * 100;
        final int PART_SIZE = 10 * 1024 * 1024;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
        final InputStream objectStreamForResult = new BoundedInputStream(fileSizeLimit);

        // Instantiate the S3 Encryption Client to encrypt and decrypt
        // by specifying a KMS Key with the kmsKeyId builder parameter.
        // enable `enableDelayedAuthenticationMode` parameter to download more than 64MB object or
        // configure buffer size using `setBufferSize()` to increase your default buffer size.
        //
        // This means that the S3 Encryption Client can perform both encrypt and decrypt operations
        // as part of the S3 putObject and getObject operations.
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableDelayedAuthenticationMode(true)
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

        // Process and Upload each part
        while ((bytesRead = inputStream.read(partData, 0, partData.length)) != -1) {
            outputStream.write(partData, 0, bytesRead);
            if (bytesSent < PART_SIZE) {
                bytesSent += bytesRead;
                continue;
            }

            // Create UploadPartRequest for each part by specifying partNumber and
            // set isLastPart as true only if the part is the last remaining part in the multipart upload.
            UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                    .bucket(BUCKET)
                    .key(objectKey)
                    .uploadId(initiateResult.uploadId())
                    .partNumber(partsSent)
                    .build();

            final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());

            // Upload all the different parts of the object
            UploadPartResponse uploadPartResult = v3Client.uploadPart(uploadPartRequest,
                    RequestBody.fromInputStream(partInputStream, partInputStream.available()));

            // We need to add eTag's of all CompletedParts before calling CompleteMultipartUpload.
            partETags.add(CompletedPart.builder()
                    .partNumber(partsSent)
                    .eTag(uploadPartResult.eTag())
                    .build());

            outputStream.reset();
            bytesSent = 0;
            partsSent++;
        }
        inputStream.close();

        // Set sdkPartType to SdkPartType.LAST for last part of the multipart upload.
        //
        // Note: Set sdkPartType parameter to SdkPartType.LAST for last part is required for Multipart Upload in S3EncryptionClient to call `cipher.doFinal()`
        UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .partNumber(partsSent)
                .sdkPartType(SdkPartType.LAST)
                .build();

        // Upload the last part multipart upload to invoke `cipher.doFinal()`
        final InputStream partInputStream = new ByteArrayInputStream(outputStream.toByteArray());
        UploadPartResponse uploadPartResult = v3Client.uploadPart(uploadPartRequest,
                RequestBody.fromInputStream(partInputStream, partInputStream.available()));

        partETags.add(CompletedPart.builder()
                .partNumber(partsSent)
                .eTag(uploadPartResult.eTag())
                .build());

        // Finally call completeMultipartUpload operation to tell S3 to merge all uploaded
        // parts and finish the multipart operation.
        v3Client.completeMultipartUpload(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .multipartUpload(partBuilder -> partBuilder.parts(partETags)));

        // Call getObject to retrieve and decrypt the object from S3
        ResponseInputStream<GetObjectResponse> output = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));

        // Asserts
        assertTrue(IOUtils.contentEquals(objectStreamForResult, output));

        // Cleanup
        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }

    /**
     * This example demonstrates a high-level approach to performing a multipart object upload to an Amazon S3 bucket
     * using the S3 Client, performing encryption and decryption operations using the AWS KMS Key Arn.
     * This allows faster putObject by creating an on-disk encrypted copy before uploading to S3.
     *
     * @throws IOException If an I/O error occurs while reading or writing data.
     */
    public static void HighLevelMultipartPutObject() throws IOException {
        final String objectKey = appendTestSuffix("high-level-multipart-upload-example");

        // Overall "file" is 100MB, split into 10MB parts
        final long fileSizeLimit = 1024 * 1024 * 100;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
        final InputStream objectStreamForResult = new BoundedInputStream(fileSizeLimit);

        // Instantiate the S3 Encryption Client to encrypt and decrypt
        // by specifying a KMS Key with the kmsKeyId builder parameter.
        // enable `enableMultipartPutObject` allows faster putObject by creating an on-disk encrypted copy before uploading to S3.
        //
        // This means that the S3 Encryption Client can perform both encrypt and decrypt operations
        // as part of the S3 putObject and getObject operations.
        // Note: You must also specify the `enableDelayedAuthenticationMode` parameter to perform getObject with more than 64MB object.
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableMultipartPutObject(true)
                .enableDelayedAuthenticationMode(true)
                .build();

        // Create an encryption context
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        // Call putObject to encrypt the object and upload it to S3.
        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
                .key(objectKey), RequestBody.fromInputStream(inputStream, fileSizeLimit));

        // Call getObject to retrieve and decrypt the object from S3.
        ResponseInputStream<GetObjectResponse> output = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
                .key(objectKey));

        // Asserts
        assertTrue(IOUtils.contentEquals(objectStreamForResult, output));

        // Cleanup
        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }
}
