package software.amazon.encryption.s3.examples;

import org.apache.commons.io.IOUtils;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.utils.BoundedZerosInputStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.S3EncryptionClient.isLastPart;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;

public class MultipartUploadExample {
    // Create a 200 character input string to use as your object in the following examples.
    // Overall "file" is 100MB, split into 10MB parts
    public static final long fileSizeLimit = 1024 * 1024 * 100;
    public static final int PART_SIZE = 10 * 1024 * 1024;
    public static String BUCKET;
    public static final String OBJECT_KEY = appendTestSuffix("multipart-upload-example");

    // This example generates a new key. In practice, you would
    // retrieve your key from an existing keystore.
    private static final SecretKey AES_KEY = retrieveAesKey();
    public static void main(final String[] args) throws IOException {
        BUCKET = args[0];
        LowLevelMultipartUpload();
        HighLevelMultipartPutObject();
        cleanup(BUCKET);
    }

    public static void LowLevelMultipartUpload() throws IOException {
        final String objectKey = "multipart-upload-v3-output-stream";

        // Overall "file" is 64MB, split into 10MB parts
        final InputStream inputStream = new BoundedZerosInputStream(fileSizeLimit);

        // Instantiate the S3 Encryption Client to encrypt and decrypt
        // by specifying an AES Key with the aesKey builder parameter.
        // You must also specify the enableDelayedAuthenticationMode parameter to upload more than 64MB object.
        //
        // This means that the S3 Encryption Client can perform both encrypt and decrypt operations
        // as part of the S3 putObject and getObject operations.
        //
        // Note: You must also specify the `enableDelayedAuthenticationMode` parameter to get an object with more than 64MB object.
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableDelayedAuthenticationMode(true)
                .build();

        // Create Multipart upload request to S3
        CreateMultipartUploadResponse initiateResult =
                v3Client.createMultipartUpload(builder -> builder.bucket(BUCKET)
                        .key(objectKey));

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

        // enable isLastPart for last part of the multipart upload.
        //
        // Note: enabling `isLastPart` for last part is required for Multipart Upload in S3EncryptionClient to call `cipher.doFinal()`
        // TODO: AWS SDK Team working on `isLastPart` as UploadPartRequest option instead of inside overrideConfiguration.
        UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .uploadId(initiateResult.uploadId())
                .partNumber(partsSent)
                .overrideConfiguration(isLastPart(true))
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

    public static void HighLevelMultipartPutObject() throws IOException {
        final String objectKey = appendTestSuffix("multipart-put-object");

        final InputStream inputStream = new BoundedZerosInputStream(fileSizeLimit);
        final InputStream objectStreamForResult = new BoundedZerosInputStream(fileSizeLimit);

        // Instantiate the S3 Encryption Client to encrypt and decrypt
        // by specifying an AES Key with the aesKey builder parameter.
        // enable `enableMultipartPutObject` allows faster putObject by creating an on-disk encrypted copy before uploading to S3.
        //
        // This means that the S3 Encryption Client can perform both encrypt and decrypt operations
        // as part of the S3 putObject and getObject operations.
        // Note: You must also specify the `enableDelayedAuthenticationMode` parameter to perform getObject with more than 64MB object.
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableMultipartPutObject(true)
                .enableDelayedAuthenticationMode(true)
                .build();

        // Call putObject to encrypt the object and upload it to S3.
        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromInputStream(inputStream, fileSizeLimit));

        // Asserts
        ResponseInputStream<GetObjectResponse> output = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));

        assertTrue(IOUtils.contentEquals(objectStreamForResult, output));

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }

    public static List<byte[]> splitFileToByteArray(File file) throws IOException {
        List<byte[]> results = new ArrayList<>();
        long fileSize = file.length();
        byte[] partBytes;
        try (FileInputStream inputStream = new FileInputStream(file)) {
            int readLength = PART_SIZE;
            while (fileSize > 0) {
                if (fileSize <= PART_SIZE) {
                    readLength = (int) fileSize;
                }
                partBytes = new byte[readLength];
                inputStream.read(partBytes, 0, readLength);
                fileSize -= readLength;
                results.add(partBytes);
            }
            inputStream.close();
            return results;
        } catch (FileNotFoundException e) {
            throw new S3EncryptionClientException("File doesn't exist for Split", e);
        }
    }

    public static void LowLevelMultipartUploadOnFile(String bucketName, String keyName, File file) throws IOException {
        // Instantiate the S3 Encryption Client to encrypt and decrypt
        // by specifying an AES Key with the aesKey builder parameter.
        S3Client s3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        try {
            // Create Multipart upload request to S3
            CreateMultipartUploadRequest createMultipartUploadRequest = CreateMultipartUploadRequest.builder()
                    .bucket(bucketName)
                    .key(keyName)
                    .build();

            CreateMultipartUploadResponse response = s3Client.createMultipartUpload(createMultipartUploadRequest);
            String uploadId = response.uploadId();

            List<byte[]> fileParts = splitFileToByteArray(file);

            List<CompletedPart> completedParts = new ArrayList<>();
            for (int i = 0; i < fileParts.size(); i++) {
                int partNumber = i + 1; // parts number should be 1 - 10000

                // Create UploadPartRequest for each part by specifying partNumber and
                // set `isLastPart` as true only if the part is the last remaining part in the multipart upload.
                UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
                        .bucket(bucketName)
                        .key(keyName)
                        .uploadId(uploadId)
                        .overrideConfiguration(isLastPart(i == (fileParts.size()-1)))
                        .partNumber(partNumber)
                        .build();
                String eTag = s3Client.uploadPart(uploadPartRequest, RequestBody.fromBytes(fileParts.get(i))).eTag();

                CompletedPart part = CompletedPart.builder().partNumber(partNumber).eTag(eTag).build();
                completedParts.add(part);
            }

            // All parts completed, notifying S3
            CompletedMultipartUpload completedMultipartUpload = CompletedMultipartUpload.builder().parts(completedParts).build();
            CompleteMultipartUploadRequest completeMultipartUploadRequest = CompleteMultipartUploadRequest.builder()
                    .bucket(bucketName)
                    .key(keyName)
                    .uploadId(uploadId)
                    .multipartUpload(completedMultipartUpload)
                    .build();

            // S3 Multipart upload succeeded.
            s3Client.completeMultipartUpload(completeMultipartUploadRequest);
        } catch (S3Exception ex) {
            throw new S3EncryptionClientException("Failed to upload to S3", ex);
        }
    }

    private static SecretKey retrieveAesKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            return keyGen.generateKey();
        } catch (final NoSuchAlgorithmException exception) {
            // This should be impossible, wrap with a runtime exception
            throw new RuntimeException(exception);
        }
    }

    private static void cleanup(String bucket) {
        // Instantiate the client to delete object
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Call deleteObject to delete the object from given S3 Bucket
        v3Client.deleteObject(builder -> builder.bucket(bucket)
                .key(OBJECT_KEY));

        // Close the client
        v3Client.close();
    }
}
