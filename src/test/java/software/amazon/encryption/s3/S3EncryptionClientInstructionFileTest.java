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
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.SdkPartType;
import software.amazon.awssdk.services.s3.model.StorageClass;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.InstructionFileConfig;
import software.amazon.encryption.s3.internal.MetadataKeyConstants;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class S3EncryptionClientInstructionFileTest {


    @Test
    public void testS3EncryptionClientInstructionFileV1V2Format() {
        final String objectKey = appendTestSuffix("simple-instruction-file-v1-v2-test");
        final String input = "testS3EncryptionClientInstructionFile";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builderV4()
                //= specification/s3-encryption/client.md#instruction-file-configuration
                //= type=test
                //# The S3EC MAY support the option to provide Instruction File Configuration during its initialization.
                //= specification/s3-encryption/client.md#instruction-file-configuration
                //= type=test
                //# If the S3EC in a given language supports Instruction Files, then it MUST accept Instruction File Configuration during its initialization.
                //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
                //= type=test
                //# Instruction File writes MUST be optionally configured during client creation or on each PutObject request.
                .instructionFileConfig(InstructionFileConfig.builder()
                        .instructionFileClient(wrappedClient)
                        .enableInstructionFilePutObject(true)
                        .build())
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .kmsKeyId(KMS_KEY_ID)
                .build();

        s3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromString(input));

        // Get the instruction file separately using a default client
        S3Client defaultClient = S3Client.create();

        ResponseBytes<GetObjectResponse> directGetResponse = defaultClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        Map<String, String> objectMetadata = directGetResponse.response().metadata();
        //= specification/s3-encryption/data-format/metadata-strategy.md#v1-v2-instruction-files
        //= type=test
        //# In the V1/V2 message format, all of the content metadata MUST be stored in the Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //= type=test
        //# The S3EC MUST support writing some or all (depending on format) content metadata to an Instruction File.
        assertFalse(objectMetadata.containsKey(MetadataKeyConstants.CONTENT_IV));
        assertFalse(objectMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2));
        assertFalse(objectMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM));
        assertFalse(objectMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_MATDESC_OR_EC));
        assertFalse(objectMetadata.containsKey(MetadataKeyConstants.CONTENT_CIPHER));

        ResponseBytes<GetObjectResponse> instructionFile = defaultClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey + ".instruction")
                .build());
        // Ensure its metadata identifies it as such
        assertTrue(instructionFile.response().metadata().containsKey("x-amz-crypto-instr-file"));
        //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //= type=test
        //# The serialized JSON string MUST be the only contents of the Instruction File.
        String instructionFileContent = instructionFile.asUtf8String();
        JsonNodeParser parser = JsonNodeParser.create();
        //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //= type=test
        //# The content metadata stored in the Instruction File MUST be serialized to a JSON string.
        Map<String, JsonNode> instructionFileMetadata = parser.parse(instructionFileContent).asObject();
        //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //= type=test
        //# The S3EC MUST support writing some or all (depending on format) content metadata to an Instruction File.
        assertTrue(instructionFileMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM));
        assertTrue(instructionFileMetadata.containsKey(MetadataKeyConstants.CONTENT_CIPHER));
        assertTrue(instructionFileMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_MATDESC_OR_EC));
        assertTrue(instructionFileMetadata.containsKey(MetadataKeyConstants.CONTENT_IV));
        assertTrue(instructionFileMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2));

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
    public void testS3EncryptionClientInstructionFileV3Format() {
        final String objectKey = appendTestSuffix("simple-instruction-file-v3-test");
        final String input = "testS3EncryptionClientInstructionFile";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builderV4()
                //= specification/s3-encryption/client.md#instruction-file-configuration
                //= type=test
                //# The S3EC MAY support the option to provide Instruction File Configuration during its initialization.
                //= specification/s3-encryption/client.md#instruction-file-configuration
                //= type=test
                //# If the S3EC in a given language supports Instruction Files, then it MUST accept Instruction File Configuration during its initialization.
                //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
                //= type=test
                //# Instruction File writes MUST be optionally configured during client creation or on each PutObject request.
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

        ResponseBytes<GetObjectResponse> directGetResponse = defaultClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());

        Map<String, String> objectMetadata = directGetResponse.response().metadata();
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=test
        //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-c" and its value in the Object Metadata when writing with an Instruction File.
        assertTrue(objectMetadata.containsKey(MetadataKeyConstants.CONTENT_CIPHER_V3));
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-d" and its value in the Object Metadata when writing with an Instruction File.
        assertTrue(objectMetadata.containsKey(MetadataKeyConstants.KEY_COMMITMENT_V3));
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-i" and its value in the Object Metadata when writing with an Instruction File.
        assertTrue(objectMetadata.containsKey(MetadataKeyConstants.MESSAGE_ID_V3));

        //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //= type=test
        //# The S3EC MUST support writing some or all (depending on format) content metadata to an Instruction File.
        assertFalse(objectMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V3));
        assertFalse(objectMetadata.containsKey(MetadataKeyConstants.ENCRYPTION_CONTEXT_V3));
        assertFalse(objectMetadata.containsKey(MetadataKeyConstants.MAT_DESC_V3));
        assertFalse(objectMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM_V3));

        ResponseBytes<GetObjectResponse> instructionFile = defaultClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey + ".instruction")
                .build());
        // Ensure its metadata identifies it as such
        assertTrue(instructionFile.response().metadata().containsKey("x-amz-crypto-instr-file"));
        //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //= type=test
        //# The serialized JSON string MUST be the only contents of the Instruction File.
        String instructionFileContent = instructionFile.asUtf8String();
        JsonNodeParser parser = JsonNodeParser.create();
        //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //= type=test
        //# The content metadata stored in the Instruction File MUST be serialized to a JSON string.
        Map<String, JsonNode> instructionFileMetadata = parser.parse(instructionFileContent).asObject();

        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST NOT store the mapkey "x-amz-c" and its value in the Instruction File.
        assertFalse(instructionFileMetadata.containsKey(MetadataKeyConstants.CONTENT_CIPHER_V3));
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST NOT store the mapkey "x-amz-d" and its value in the Instruction File.
        assertFalse(instructionFileMetadata.containsKey(MetadataKeyConstants.KEY_COMMITMENT_V3));
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST NOT store the mapkey "x-amz-i" and its value in the Instruction File.
        assertFalse(instructionFileMetadata.containsKey(MetadataKeyConstants.MESSAGE_ID_V3));

        //= specification/s3-encryption/data-format/metadata-strategy.md#instruction-file
        //= type=test
        //# The S3EC MUST support writing some or all (depending on format) content metadata to an Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-3" and its value in the Instruction File.
        assertTrue(instructionFileMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V3));
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //= type=test
        //# - The V3 message format MUST store the mapkey "x-amz-w" and its value in the Instruction File.
        assertTrue(instructionFileMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM_V3));
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
    public void testV4TransitionInstructionFileExists() {
        final String objectKey = appendTestSuffix("instruction-file-put-object");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
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
    public void testV4InstructionFileExists() {
        final String objectKey = appendTestSuffix("instruction-file-put-object");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builderV4()
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
    public void testV4TransitionDisabledClientFails() {
        final String objectKey = appendTestSuffix("instruction-file-put-object-disabled-fails");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
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
        S3Client s3ClientDisabledInstructionFile = S3EncryptionClient.builderV4()
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

    @Test
    public void testV4DisabledClientFails() {
        final String objectKey = appendTestSuffix("instruction-file-put-object-disabled-fails");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builderV4()
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
        S3Client s3ClientDisabledInstructionFile = S3EncryptionClient.builderV4()
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
    public void testV4TransitionInstructionFileDelete() {
        final String objectKey = appendTestSuffix("instruction-file-put-object-delete");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
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
    public void testV4InstructionFileDelete() {
        final String objectKey = appendTestSuffix("instruction-file-put-object-delete");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builderV4()
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
    public void testPutWithInstructionFileV4TransitionToV2Kms() {
        final String objectKey = appendTestSuffix("instruction-file-put-object-v3-to-v2-kms");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
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
    public void testPutWithInstructionFileV4TransitionToV2Aes() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();
        final String objectKey = appendTestSuffix("instruction-file-put-object-v3-to-v2-aes");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
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
    public void testPutWithInstructionFileV4TransitionToV2Rsa() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair rsaKey = keyPairGen.generateKeyPair();

        final String objectKey = appendTestSuffix("instruction-file-put-object-v3-to-v2-rsa");
        final String input = "SimpleTestOfV3EncryptionClient";
        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
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
    public void testV4TransitionMultipartPutWithInstructionFile() throws IOException {
        final String object_key = appendTestSuffix("test-multipart-put-instruction-file");

        final long fileSizeLimit = 1024 * 1024 * 50; //50 MB
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
        final InputStream objectStreamForResult = new BoundedInputStream(fileSizeLimit);
        final StorageClass storageClass = StorageClass.STANDARD_IA;

        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
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

    }

    @Test
    public void testV4MultipartPutWithInstructionFile() throws IOException {
        final String object_key = appendTestSuffix("test-multipart-put-instruction-file");

        final long fileSizeLimit = 1024 * 1024 * 50; //50 MB
        final InputStream inputStream = new BoundedInputStream(fileSizeLimit);
        final InputStream objectStreamForResult = new BoundedInputStream(fileSizeLimit);
        final StorageClass storageClass = StorageClass.STANDARD_IA;

        S3Client wrappedClient = S3Client.create();
        S3Client s3Client = S3EncryptionClient.builderV4()
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

    }

    @Test
    public void testV4TransitionLowLevelMultipartPutWithInstructionFile() throws NoSuchAlgorithmException, IOException {
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

        S3Client s3Client = S3EncryptionClient.builderV4()
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .rsaKeyPair(rsaKey)
                .instructionFileConfig(InstructionFileConfig.builder()
                        .instructionFileClient(wrappedClient)
                        .enableInstructionFilePutObject(true)
                        .build())
                .enableDelayedAuthenticationMode(true)
                .build();


        CreateMultipartUploadResponse initiateResult = s3Client.createMultipartUpload(builder ->
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

            UploadPartResponse uploadPartResult = s3Client.uploadPart(uploadPartRequest,
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
        UploadPartResponse uploadPartResult = s3Client.uploadPart(uploadPartRequest,
                RequestBody.fromInputStream(partInputStream, partInputStream.available()));
        partETags.add(CompletedPart.builder()
                .partNumber(partsSent)
                .eTag(uploadPartResult.eTag())
                .build());
        s3Client.completeMultipartUpload(builder -> builder
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

        ResponseInputStream<GetObjectResponse> getResponse = s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(object_key));

        assertTrue(IOUtils.contentEquals(objectStreamForResult, getResponse));

        deleteObject(BUCKET, object_key, s3Client);
        s3Client.close();
    }

    @Test
    public void testV4LowLevelMultipartPutWithInstructionFile() throws NoSuchAlgorithmException, IOException {
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

        S3Client s3Client = S3EncryptionClient.builderV4()
                .rsaKeyPair(rsaKey)
                .instructionFileConfig(InstructionFileConfig.builder()
                        .instructionFileClient(wrappedClient)
                        .enableInstructionFilePutObject(true)
                        .build())
                .enableDelayedAuthenticationMode(true)
                .build();


        CreateMultipartUploadResponse initiateResult = s3Client.createMultipartUpload(builder ->
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

            UploadPartResponse uploadPartResult = s3Client.uploadPart(uploadPartRequest,
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
        UploadPartResponse uploadPartResult = s3Client.uploadPart(uploadPartRequest,
                RequestBody.fromInputStream(partInputStream, partInputStream.available()));
        partETags.add(CompletedPart.builder()
                .partNumber(partsSent)
                .eTag(uploadPartResult.eTag())
                .build());
        s3Client.completeMultipartUpload(builder -> builder
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

        ResponseInputStream<GetObjectResponse> getResponse = s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(object_key));

        assertTrue(IOUtils.contentEquals(objectStreamForResult, getResponse));

        deleteObject(BUCKET, object_key, s3Client);
        s3Client.close();
    }

}

