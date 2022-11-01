package software.amazon.encryption.s3;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.*;
import com.amazonaws.services.s3.model.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalEncryptionContext;

/**
 * This class is an integration test for verifying compatibility of ciphertexts
 * between V1, V2, and V3 clients under various conditions.
 */
public class S3EncryptionClientRangedGetCompatibilityTestCopy {

    private static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");
    private static final String KMS_KEY_ID = System.getenv("AWS_S3EC_TEST_KMS_KEY_ID");
    private static final Region KMS_REGION = Region.getRegion(Regions.fromName(System.getenv("AWS_REGION")));
    private static final String KMS_KEY_ALIAS = System.getenv("AWS_S3EC_TEST_KMS_KEY_ALIAS");


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
    public void RangedGet() {
        final String BUCKET_KEY = "ranged-get";
        S3Client client = S3Client.builder().build();
        final String input = "0123456789012345678901234567890123456789";

        client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY), RequestBody.fromString(input));
        ResponseBytes<GetObjectResponse> output = client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=41-45")
                .key(BUCKET_KEY));
        assertEquals("", output.asUtf8String());
    }

    @Test
    public void AesCbcV1toV3() {
        final String BUCKET_KEY = "aes-cbc-v1-to-v3";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.EncryptionOnly);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Asserts
        final String input = "AesCbcV1toV3";
        //v1Client.putObject(, RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void AesCbcV1toV3RangedGet() {
        final String BUCKET_KEY = "aes-cbc-v1-to-v3-ranged-get";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration();
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";

        v1Client.putObject(BUCKET, BUCKET_KEY, input);

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyUnauthenticatedModes(true)
                .build();
        int i,j;
        i=199;
        j=200;
        int finalJ = j;
        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes="+ i +"-"+ finalJ)
                .key(BUCKET_KEY));
        if (j>=input.length()) {
            j = input.length();
        } else j++;
        // Zero's are padded towards the end
        String output = objectResponse.asUtf8String();
        assertEquals(input.substring(i,j), output);
    }

    @Test
    public void AesCbcV1toV3RangedGetAllRanges() {
        final String BUCKET_KEY = "aes-cbc-v1-to-v3-ranged-get";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration();
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";

        v1Client.putObject(BUCKET, BUCKET_KEY, input);

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyUnauthenticatedModes(true)
                .build();
        for(int i=0; i<input.length(); i=i+5) {
            for(int j=input.length()-8; j>i; j=j-3) {
                int finalJ = j;
                int finalI = i;
                ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                        .bucket(BUCKET)
                        .range("bytes="+ finalI +"-"+ finalJ)
                        .key(BUCKET_KEY));
                if (j>=input.length()) {
                    j = input.length();
                } else j++;
                String output = objectResponse.asUtf8String();
                assertEquals(input.substring(i,j), output);
            }
        }
    }

    @Test
    public void AesCbcV1toV2RangedGet() throws IOException {
        final String BUCKET_KEY = "aes-cbc-v1-to-v3-ranged-get";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration();
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        CryptoConfigurationV2 v2CryptoConfig =
                new CryptoConfigurationV2(CryptoMode.AuthenticatedEncryption)
                        .withRangeGetMode(CryptoRangeGetMode.ALL);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCryptoConfiguration(v2CryptoConfig)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // Asserts
        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";

        v2Client.putObject(BUCKET, BUCKET_KEY, input);
        GetObjectRequest getObjectRequest = new GetObjectRequest(BUCKET, BUCKET_KEY);
        getObjectRequest.setRange(250,220);
        S3Object output1 = v2Client.getObject(getObjectRequest);
        byte[] outputbytes = output1.getObjectContent().readAllBytes();
        String outputAsString = new String(outputbytes);
        assertEquals("", outputAsString);
    }

    @Test
    public void AesWrapV1toV3() {
        final String BUCKET_KEY = "aes-wrap-v1-to-v3";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Asserts
        final String input = "AesGcmV1toV3";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void AesWrapV1toV2() {
        final String BUCKET_KEY = "aes-wrap-v1-to-v3";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration();
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V2 Client
        CryptoConfigurationV2 v2CryptoConfig = new CryptoConfigurationV2()
                .withCryptoMode(CryptoMode.AuthenticatedEncryption);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCryptoConfiguration(v2CryptoConfig)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // Asserts
        final String input = "AesGcmV1toV3";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);

        String output = v2Client.getObjectAsString(BUCKET, BUCKET_KEY);
        //String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void AesGcmV2toV3() {
        final String BUCKET_KEY = "aes-gcm-v2-to-v3";

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";
        v2Client.putObject(BUCKET, BUCKET_KEY, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=190-198")
                .key(BUCKET_KEY));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

//    @Test
//    public void AesGcmV2toV3WithInstructionFile() {
//        final String BUCKET_KEY = "aes-gcm-v2-to-v3-with-instruction-file";
//
//        // V2 Client
//        EncryptionMaterialsProvider materialsProvider =
//                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
//        CryptoConfigurationV2 cryptoConfig =
//                new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
//                        .withStorageMode(CryptoStorageMode.InstructionFile);
//        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
//                .withCryptoConfiguration(cryptoConfig)
//                .withEncryptionMaterialsProvider(materialsProvider)
//                .build();
//
//        // V3 Client
//        S3Client v3Client = S3EncryptionClient.builder()
//                .aesKey(AES_KEY)
//                .build();
//
//        // Asserts
//        final String input = "AesGcmV2toV3";
//        v2Client.putObject(BUCKET, BUCKET_KEY, input);
//
//        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(
//                GetObjectRequest.builder()
//                        .bucket(BUCKET)
//                        .key(BUCKET_KEY).build());
//        String output = objectResponse.asUtf8String();
//        assertEquals(input, output);
//    }

    @Test
    public void AesGcmV3toV1() throws IOException {
        final String BUCKET_KEY = "aes-gcm-v3-to-v1";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";
        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY), RequestBody.fromString(input));
        GetObjectRequest getObjectRequest = new GetObjectRequest(BUCKET, BUCKET_KEY);
        getObjectRequest.setRange(230,290);
        S3Object output = v1Client.getObject(getObjectRequest);
//        System.out.println(new String(output.getObjectContent().readAllBytes()));
//        assertEquals(input, output.getObjectContent().readAllBytes().toString());
    }

    @Test
    public void AesGcmV3toV2() {
        final String BUCKET_KEY = "aes-gcm-v3-to-v2";

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmV3toV2";
        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY), RequestBody.fromString(input));

        String output = v2Client.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
    }

    @Test
    public void AesGcmV3toV3RangedGet() {
        final String BUCKET_KEY = "aes-gcm-v3-to-v3";

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "0bcdefghijklmnopqrst0BCDEFGHIJKLMNOPQRST" +
                "1bcdefghijklmnopqrst1BCDEFGHIJKLMNOPQRST" +
                "2bcdefghijklmnopqrst2BCDEFGHIJKLMNOPQRST" +
                "3bcdefghijklmnopqrst3BCDEFGHIJKLMNOPQRST" +
                "4bcdefghijklmnopqrst4BCDEFGHIJKLMNOPQRST";

        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .range("bytes=0-10")
                .key(BUCKET_KEY));
        String output = objectResponse.asUtf8String();
        assertEquals("KLMNOPQRST", output);
    }

    @Test
    public void RsaEcbV1toV3() {
        final String BUCKET_KEY = "rsa-ecb-v1-to-v3";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Asserts
        final String input = "RsaEcbV1toV3";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void RsaOaepV2toV3() {
        final String BUCKET_KEY = "rsa-oaep-v2-to-v3";

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        CryptoConfigurationV2 cryptoConfig =
                new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCryptoConfiguration(cryptoConfig)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        // Asserts
        final String input = "RsaOaepV2toV3";
        v2Client.putObject(BUCKET, BUCKET_KEY, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void RsaOaepV3toV1() {
        final String BUCKET_KEY = "rsa-oaep-v3-to-v1";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        // Asserts
        final String input = "RsaOaepV3toV1";
        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY), RequestBody.fromString(input));

        String output = v1Client.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
    }

    @Test
    public void RsaOaepV3toV2() {
        final String BUCKET_KEY = "rsa-oaep-v3-to-v2";

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(RSA_KEY_PAIR));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        // Asserts
        final String input = "RsaOaepV3toV2";
        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY), RequestBody.fromString(input));

        String output = v2Client.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
    }

    @Test
    public void RsaOaepV3toV3() {
        final String BUCKET_KEY = "rsa-oaep-v3-to-v3";

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        // Asserts
        final String input = "RsaOaepV3toV3";
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void KmsV1toV3() {
        final String BUCKET_KEY = "kms-v1-to-v3";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Asserts
        final String input = "KmsV1toV3";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void KmsV1toV2Builde() {
        final String BUCKET_KEY = "kms-v1-to-v2-builder";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        EncryptionMaterialsProvider materialsProvider2 = new KMSEncryptionMaterialsProvider(KMS_KEY_ALIAS);

        CryptoConfiguration v1Config =
                new CryptoConfiguration()
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClientBuilder.standard()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V2 client
        CryptoConfigurationV2 v2Config =
                new CryptoConfigurationV2()
                        .withAwsKmsRegion(KMS_REGION)
                        .withCryptoMode(CryptoMode.AuthenticatedEncryption);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2Builder.standard()
                .withCryptoConfiguration(v2Config)
                .withEncryptionMaterialsProvider(materialsProvider2)
                .build();

        // Asserts
        final String input = "KmsV1toV2";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);
        String output = v2Client.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
    }

    @Test
    public void KmsV1toV2() {
        final String BUCKET_KEY = "kms-v1-to-v2";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        CryptoConfiguration v1Config =
                new CryptoConfiguration()
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();
        // V2 client
        CryptoConfigurationV2 v2Config =
                new CryptoConfigurationV2(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCryptoConfiguration(v2Config)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();


        // Asserts
        final String input = "KmsV1toV3";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);
        String output = v2Client.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
    }

    @Test
    public void KmsContextV2toV3() {
        final String BUCKET_KEY = "kms-context-v2-to-v3";

        // V2 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Asserts
        final String input = "KmsContextV2toV3";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value");
        EncryptedPutObjectRequest putObjectRequest = new EncryptedPutObjectRequest(
                BUCKET,
                BUCKET_KEY,
                new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)),
                null
        ).withMaterialsDescription(encryptionContext);
        v2Client.putObject(putObjectRequest);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .overrideConfiguration(withAdditionalEncryptionContext(encryptionContext)));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void KmsContextV3toV1() {
        final String BUCKET_KEY = "kms-context-v3-to-v1";

        // V1 Client
        KMSEncryptionMaterials kmsMaterials = new KMSEncryptionMaterials(KMS_KEY_ID);
        kmsMaterials.addDescription("user-metadata-key", "user-metadata-value-v3-to-v1");
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(kmsMaterials);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Asserts
        final String input = "KmsContextV3toV1";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v1");

        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .overrideConfiguration(withAdditionalEncryptionContext(encryptionContext)), RequestBody.fromString(input));

        String output = v1Client.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
    }

    @Test
    public void KmsContextV3toV2() throws IOException {
        final String BUCKET_KEY = "kms-context-v3-to-v2";

        // V2 Client
        KMSEncryptionMaterials kmsMaterials = new KMSEncryptionMaterials(KMS_KEY_ID);
        kmsMaterials.addDescription("user-metadata-key", "user-metadata-value-v3-to-v2");
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(kmsMaterials);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Asserts
        final String input = "KmsContextV3toV2";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v2");

        v3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(BUCKET_KEY)
                        .overrideConfiguration(withAdditionalEncryptionContext(encryptionContext)),
                RequestBody.fromString(input));

        String output = v2Client.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
    }

    @Test
    public void KmsContextV3toV3() {
        final String BUCKET_KEY = "kms-context-v3-to-v3";

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Asserts
        final String input = "KmsContextV3toV3";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3");

        v3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(BUCKET_KEY)
                        .overrideConfiguration(withAdditionalEncryptionContext(encryptionContext)),
                RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .overrideConfiguration(withAdditionalEncryptionContext(encryptionContext)));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void AesCbcV1toV3FailsWhenLegacyModeDisabled() {
        final String BUCKET_KEY = "aes-cbc-v1-to-v3";

        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.EncryptionOnly);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyUnauthenticatedModes(false)
                .build();

        final String input = "AesCbcV1toV3";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);

        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY)));
    }

    @Test
    public void AesWrapV1toV3FailsWhenLegacyModeDisabled() {
        final String BUCKET_KEY = "aes-wrap-v1-to-v3";

        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfiguration v1CryptoConfig =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption);
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1CryptoConfig)
                .withEncryptionMaterials(materialsProvider)
                .build();

        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyUnauthenticatedModes(false)
                .build();

        final String input = "AesGcmV1toV3";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);

        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY)));
    }

}
