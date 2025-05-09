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
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.encryption.s3.internal.InstructionFileConfig;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

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
}
