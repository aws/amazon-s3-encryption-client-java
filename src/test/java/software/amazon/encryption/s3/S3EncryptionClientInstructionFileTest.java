package software.amazon.encryption.s3;

import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.CryptoConfigurationV2;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.KMSEncryptionMaterials;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.SdkPartType;
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.encryption.s3.internal.InstructionFileConfig;
import software.amazon.encryption.s3.utils.BoundedInputStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class S3EncryptionClientInstructionFileTest {

    @Test
    public void testInstructionFileExists() {
        final String objectKey = appendTestSuffix("instruction-file-put-object");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builder()
          .instructionFileConfig(InstructionFileConfig.builder()
            .instructionFileClient(wrappedClient)
            .enableInstructionFilePutObject(true)
            .build())
          .kmsKeyId(KMS_KEY_ID)
          .build();

        s3Client.putObject(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .build(), RequestBody.fromString(input));

        // Get the instruction file separately using a default client
        S3Client defaultClient = S3Client.create();
        ResponseBytes<GetObjectResponse> directInstGetResponse = defaultClient.getObjectAsBytes(builder -> builder
          .bucket(BUCKET)
          .key(objectKey + ".instruction")
          .build());
        // Ensure its metadata identifies it as such
        assertTrue(directInstGetResponse.response().metadata().containsKey("x-amz-crypto-instr-file"));

        // Ensure decryption succeeds
        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
        defaultClient.close();
    }

    @Test
    public void testDisabledClientFails() {
        final String objectKey = appendTestSuffix("instruction-file-put-object-disabled-fails");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builder()
          .instructionFileConfig(InstructionFileConfig.builder()
            .instructionFileClient(wrappedClient)
            .enableInstructionFilePutObject(true)
            .build())
          .kmsKeyId(KMS_KEY_ID)
          .build();

        // Put with Instruction File
        s3Client.putObject(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .build(), RequestBody.fromString(input));

        // Disabled client should fail
        S3Client s3ClientDisabledInstructionFile = S3EncryptionClient.builder()
          .wrappedClient(wrappedClient)
          .instructionFileConfig(InstructionFileConfig.builder()
            .disableInstructionFile(true)
            .build())
          .kmsKeyId(KMS_KEY_ID)
          .build();

        try {
            s3ClientDisabledInstructionFile.getObjectAsBytes(builder -> builder
              .bucket(BUCKET)
              .key(objectKey)
              .build());
            fail("expected exception");
        } catch (S3EncryptionClientException exception) {
            assertTrue(exception.getMessage().contains("Exception encountered while fetching Instruction File."));
        }

        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
        s3ClientDisabledInstructionFile.close();
    }


    /**
     * This test is somewhat redundant given deletion itself is tested in
     * e.g. deleteObjectWithInstructionFileSuccess, but is included anyway to be thorough
     */
    @Test
    public void testInstructionFileDelete() {
        final String objectKey = appendTestSuffix("instruction-file-put-object-delete");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builder()
          .instructionFileConfig(InstructionFileConfig.builder()
            .instructionFileClient(wrappedClient)
            .enableInstructionFilePutObject(true)
            .build())
          .kmsKeyId(KMS_KEY_ID)
          .build();

        s3Client.putObject(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .build(), RequestBody.fromString(input));

        // Get the instruction file separately using a default client
        S3Client defaultClient = S3Client.create();
        ResponseBytes<GetObjectResponse> directInstGetResponse = defaultClient.getObjectAsBytes(builder -> builder
          .bucket(BUCKET)
          .key(objectKey + ".instruction")
          .build());
        // Ensure its metadata identifies it as such
        assertTrue(directInstGetResponse.response().metadata().containsKey("x-amz-crypto-instr-file"));

        // Ensure decryption succeeds
        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        deleteObject(BUCKET, objectKey, s3Client);

        try {
            defaultClient.getObjectAsBytes(builder -> builder
              .bucket(BUCKET)
              .key(objectKey + ".instruction")
              .build());
            fail("expected exception!");
        } catch (NoSuchKeyException e) {
            // expected
        }

        s3Client.close();
        defaultClient.close();
    }

    @Test
    public void testPutWithInstructionFileV3ToV2Kms() {
        final String objectKey = appendTestSuffix("instruction-file-put-object-v3-to-v2-kms");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builder()
          .instructionFileConfig(InstructionFileConfig.builder()
            .instructionFileClient(wrappedClient)
            .enableInstructionFilePutObject(true)
            .build())
          .kmsKeyId(KMS_KEY_ID)
          .build();

        s3Client.putObject(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .build(), RequestBody.fromString(input));

        EncryptionMaterialsProvider materialsProvider =
          new StaticEncryptionMaterialsProvider(new KMSEncryptionMaterials(KMS_KEY_ID));
        CryptoConfigurationV2 cryptoConfig =
          new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
            .withStorageMode(CryptoStorageMode.InstructionFile);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
          .withCryptoConfiguration(cryptoConfig)
          .withEncryptionMaterialsProvider(materialsProvider)
          .build();

        String result = v2Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, result);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void testPutWithInstructionFileV3ToV2Aes() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();
        final String objectKey = appendTestSuffix("instruction-file-put-object-v3-to-v2-aes");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builder()
          .instructionFileConfig(InstructionFileConfig.builder()
            .instructionFileClient(wrappedClient)
            .enableInstructionFilePutObject(true)
            .build())
          .aesKey(aesKey)
          .build();

        s3Client.putObject(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .build(), RequestBody.fromString(input));

        EncryptionMaterialsProvider materialsProvider =
          new StaticEncryptionMaterialsProvider(new EncryptionMaterials(aesKey));
        CryptoConfigurationV2 cryptoConfig =
          new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
            .withStorageMode(CryptoStorageMode.InstructionFile);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
          .withCryptoConfiguration(cryptoConfig)
          .withEncryptionMaterialsProvider(materialsProvider)
          .build();

        String result = v2Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, result);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void testPutWithInstructionFileV3ToV2Rsa() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair rsaKey = keyPairGen.generateKeyPair();

        final String objectKey = appendTestSuffix("instruction-file-put-object-v3-to-v2-rsa");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builder()
          .instructionFileConfig(InstructionFileConfig.builder()
            .instructionFileClient(wrappedClient)
            .enableInstructionFilePutObject(true)
            .build())
          .rsaKeyPair(rsaKey)
          .build();

        s3Client.putObject(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .build(), RequestBody.fromString(input));

        EncryptionMaterialsProvider materialsProvider =
          new StaticEncryptionMaterialsProvider(new EncryptionMaterials(rsaKey));
        CryptoConfigurationV2 cryptoConfig =
          new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
            .withStorageMode(CryptoStorageMode.InstructionFile);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
          .withCryptoConfiguration(cryptoConfig)
          .withEncryptionMaterialsProvider(materialsProvider)
          .build();

        String result = v2Client.getObjectAsString(BUCKET, objectKey);
        assertEquals(input, result);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @Test
    public void testMultipartPutWithInstructionFile() throws IOException {
        int success = 0, failures = 0;
        for(int i=0; i < 100; i++) {
            try {
                final String object_key = appendTestSuffix("test-multipart-put-instruction-file");

                final long fileSizeLimit = 1024 * 1024 * 50; //50 MB
                final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
                final InputStream objectStreamForResult = new BoundedInputStream(fileSizeLimit);
                final StorageClass storageClass = StorageClass.STANDARD_IA;

                S3Client wrappedClient = S3Client.create();
                S3Client s3Client = S3EncryptionClient.builder()
                  .instructionFileConfig(InstructionFileConfig.builder()
                    .instructionFileClient(wrappedClient)
                    .enableInstructionFilePutObject(true)
                    .build())
                  .kmsKeyId(KMS_KEY_ID)
                  .enableMultipartPutObject(true)
                  .build();

                Map<String, String> encryptionContext = new HashMap<>();
                encryptionContext.put("test-key", "test-value");


                s3Client.putObject(builder -> builder
                  .bucket(BUCKET)
                  .storageClass(storageClass)
                  .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
                  .key(object_key), RequestBody.fromInputStream(inputStream, fileSizeLimit));

                S3Client defaultClient = S3Client.create();
                ResponseBytes<GetObjectResponse> directInstGetResponse = defaultClient.getObjectAsBytes(builder -> builder
                  .bucket(BUCKET)
                  .key(object_key + ".instruction")
                  .build());
                assertTrue(directInstGetResponse.response().metadata().containsKey("x-amz-crypto-instr-file"));
                assertEquals(storageClass.toString(), directInstGetResponse.response().storageClassAsString());

                ResponseInputStream<GetObjectResponse> getResponse = s3Client.getObject(builder -> builder
                  .bucket(BUCKET)
                  .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
                  .key(object_key));

                assertTrue(IOUtils.contentEquals(objectStreamForResult, getResponse));

                deleteObject(BUCKET, object_key, s3Client);
                s3Client.close();

                success++;
            } catch (Exception e) {
                failures++;
            }
        }
        System.out.println("testMultipartPutWithInstructionFile: Success: "+success+" Failures: "+failures);

    }

    @Test
    public void testLowLevelMultipartPutWithInstructionFile() throws NoSuchAlgorithmException, IOException {
        final String object_key = appendTestSuffix("test-low-level-multipart-put-instruction-file");

        final long fileSizeLimit = 1024 * 1024 * 50;
        final int PART_SIZE = 10 * 1024 * 1024;
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
        final InputStream objectStreamForResult = new BoundedInputStream(fileSizeLimit);
        final StorageClass storageClass = StorageClass.STANDARD_IA;

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair rsaKey = keyPairGen.generateKeyPair();

        S3Client wrappedClient = S3Client.create();

        S3Client v3Client = S3EncryptionClient.builder()
          .rsaKeyPair(rsaKey)
          .instructionFileConfig(InstructionFileConfig.builder()
            .instructionFileClient(wrappedClient)
            .enableInstructionFilePutObject(true)
            .build())
          .enableDelayedAuthenticationMode(true)
          .build();


        CreateMultipartUploadResponse initiateResult = v3Client.createMultipartUpload(builder ->
          builder.bucket(BUCKET).key(object_key).storageClass(storageClass));

        List<CompletedPart> partETags = new ArrayList<>();

        int bytesRead, bytesSent = 0;
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
              .key(object_key)
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
        UploadPartRequest uploadPartRequest = UploadPartRequest.builder()
          .bucket(BUCKET)
          .key(object_key)
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
        v3Client.completeMultipartUpload(builder -> builder
          .bucket(BUCKET)
          .key(object_key)
          .uploadId(initiateResult.uploadId())
          .multipartUpload(partBuilder -> partBuilder.parts(partETags)));

        S3Client defaultClient = S3Client.create();
        ResponseBytes<GetObjectResponse> directInstGetResponse = defaultClient.getObjectAsBytes(builder -> builder
          .bucket(BUCKET)
          .key(object_key + ".instruction")
          .build());
        assertTrue(directInstGetResponse.response().metadata().containsKey("x-amz-crypto-instr-file"));
        assertEquals(storageClass.toString(), directInstGetResponse.response().storageClassAsString());

        ResponseInputStream<GetObjectResponse> getResponse = v3Client.getObject(builder -> builder
          .bucket(BUCKET)
          .key(object_key));

        assertTrue(IOUtils.contentEquals(objectStreamForResult, getResponse));

        deleteObject(BUCKET, object_key, v3Client);
        v3Client.close();
    }

}
