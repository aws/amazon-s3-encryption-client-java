package software.amazon.encryption.s3;

import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.CryptoConfigurationV2;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.KMSEncryptionMaterials;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.encryption.s3.internal.InstructionFileConfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
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
    public void testPutWithInstructionFile() {
        final String objectKey = appendTestSuffix("instruction-file-put-object");
        final String objectKeyV2 = appendTestSuffix("instruction-file-put-object-v2");
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
        assertTrue(directInstGetResponse.response().metadata().containsKey("x-amz-crypto-instr-file"));

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Temporary - Generate an instruction file in V2 to compare against V3
        // TODO: do this for other keyrings as well
        // TODO: Instead, make a V3ToV2 test
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new KMSEncryptionMaterials(KMS_KEY_ID));
        CryptoConfigurationV2 cryptoConfig =
                new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
                        .withStorageMode(CryptoStorageMode.InstructionFile);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCryptoConfiguration(cryptoConfig)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        v2Client.putObject(BUCKET, objectKeyV2, input);

        // Cleanup
//        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }
}
