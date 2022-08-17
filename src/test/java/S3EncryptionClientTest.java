import static org.junit.jupiter.api.Assertions.assertEquals;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.*;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClient;

public class S3EncryptionClientTest {

    // TODO: make these dynamic
    private static final String BUCKET = "845853869857-s3-research";

    private static final String KMS_MASTER_KEY = "e45015eb-1643-448f-9145-8ed4679138e4";
    
    private static final Region KMS_REGION = Region.getRegion(Regions.US_EAST_2);

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
                .enableLegacyModes(true)
                .build();

        // Asserts
        final String input = "AesCbcV1toV3";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY).build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
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
                .enableLegacyModes(true)
                .build();

        // Asserts
        final String input = "AesGcmV1toV3";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY).build());
        String output = objectResponse.asUtf8String();
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
        final String input = "AesGcmV2toV3";
        v2Client.putObject(BUCKET, BUCKET_KEY, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(
                GetObjectRequest.builder()
                        .bucket(BUCKET)
                        .key(BUCKET_KEY).build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void AesGcmV2toV3WithInstructionFile() {
        final String BUCKET_KEY = "aes-gcm-v2-to-v3-with-instruction-file";

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfigurationV2 cryptoConfig =
                new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
                        .withStorageMode(CryptoStorageMode.InstructionFile);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCryptoConfiguration(cryptoConfig)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmV2toV3";
        v2Client.putObject(BUCKET, BUCKET_KEY, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(
                GetObjectRequest.builder()
                        .bucket(BUCKET)
                        .key(BUCKET_KEY).build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void AesGcmV3toV1() {
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
        final String input = "AesGcmV3toV1";
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), RequestBody.fromString(input));

        String output = v1Client.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
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
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), RequestBody.fromString(input));

        String output = v2Client.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
    }

    @Test
    public void AesGcmV3toV3() {
        final String BUCKET_KEY = "aes-gcm-v3-to-v3";

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmV3toV3";
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(
                GetObjectRequest.builder()
                        .bucket(BUCKET)
                        .key(BUCKET_KEY).build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
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
                .enableLegacyModes(true)
                .build();

        // Asserts
        final String input = "RsaEcbV1toV3";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY).build());
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

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(
                GetObjectRequest.builder()
                        .bucket(BUCKET)
                        .key(BUCKET_KEY).build());
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
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), RequestBody.fromString(input));

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
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), RequestBody.fromString(input));

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

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(
                GetObjectRequest.builder()
                        .bucket(BUCKET)
                        .key(BUCKET_KEY).build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void KmsV1toV3() {
        final String BUCKET_KEY = "kms-v1-to-v3";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_MASTER_KEY);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_MASTER_KEY)
                .enableLegacyModes(true)
                .build();

        // Asserts
        final String input = "KmsV1toV3";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY).build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void KmsContextV2toV3() {
        final String BUCKET_KEY = "kms-context-v2-to-v3";

        // V2 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_MASTER_KEY);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_MASTER_KEY)
                .enableLegacyModes(true)
                .build();

        // Asserts
        final String input = "KmsContextV2toV3";
        ObjectMetadata objectMetadata = new ObjectMetadata();
        objectMetadata.addUserMetadata("user-metadata-key", "user-metadata-value");
        EncryptedPutObjectRequest putObjectRequest = new EncryptedPutObjectRequest(
                BUCKET,
                BUCKET_KEY,
                new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)),
                objectMetadata
        );
        v2Client.putObject(putObjectRequest);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY).build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }

    @Test
    public void KmsContextV3toV1() {
        final String BUCKET_KEY = "kms-context-v3-to-v1";

        // V1 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_MASTER_KEY);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_MASTER_KEY)
                .enableLegacyModes(true)
                .build();

        // Asserts
        final String input = "KmsContextV3toV1";
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), RequestBody.fromString(input));

        String output = v1Client.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
    }

    @Test
    public void KmsContextV3toV2() {
        final String BUCKET_KEY = "kms-context-v3-to-v2";

        // V2 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_MASTER_KEY);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_MASTER_KEY)
                .enableLegacyModes(true)
                .build();

        // Asserts
        final String input = "KmsContextV3toV2";
        // TODO: need to add encryption context to the V3 request somehow
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), RequestBody.fromString(input));

        String output = v2Client.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
    }

    @Test
    public void KmsContextV3toV3() {
        final String BUCKET_KEY = "kms-context-v3-to-v3";

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_MASTER_KEY)
                .enableLegacyModes(true)
                .build();

        // Asserts
        final String input = "KmsContextV3toV3";
        // TODO: need to add encryption context to the V3 request somehow
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY).build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }
}
