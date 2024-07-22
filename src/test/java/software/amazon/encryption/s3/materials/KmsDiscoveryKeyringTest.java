package software.amazon.encryption.s3.materials;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class KmsDiscoveryKeyringTest {
    private static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");
    private static final String KMS_KEY_ID = System.getenv("AWS_S3EC_TEST_KMS_KEY_ID");
    private static final Region KMS_REGION = Region.getRegion(Regions.fromName(System.getenv("AWS_REGION")));

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
    public void buildKmsDiscoveryKeyringWithNullSecureRandomFails() {
      assertThrows(S3EncryptionClientException.class, () -> KmsDiscoveryKeyring.builder().secureRandom(null));
    }

    @Test
    public void buildDiscoveryKeyringWithNullDataKeyGeneratorFails() {
      assertThrows(S3EncryptionClientException.class, () -> KmsDiscoveryKeyring.builder().dataKeyGenerator(null));
    }

    @Test
    public void testKmsDiscovery() {
        final String objectKey = appendTestSuffix("kms-v1-to-v3-discovery");

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
        KmsDiscoveryKeyring kmsDiscoveryKeyring = KmsDiscoveryKeyring
          .builder().enableLegacyWrappingAlgorithms(true).build();
        S3Client v3Client = S3EncryptionClient.builder()
                .keyring(kmsDiscoveryKeyring)
                .build();

        // Asserts
        final String input = "KMS Discovery Keyring";
        v1Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void testKmsContextDiscovery() {
        final String objectKey = appendTestSuffix("kms-v3-to-v3-discovery-context");

        // V3 Client - KmsKeyring
        S3Client v3Client = S3EncryptionClient.builder()
          .kmsKeyId(KMS_KEY_ID)
          .build();

        final String input = "KmsContextV3toV1Discovery";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3-context");

        v3Client.putObject(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .overrideConfiguration(withAdditionalConfiguration(encryptionContext)), RequestBody.fromString(input));

        // V3 Client - KmsDiscoveryContext
        KmsDiscoveryKeyring kmsDiscoveryKeyring = KmsDiscoveryKeyring
          .builder().enableLegacyWrappingAlgorithms(true).build();
        S3Client v3ClientDiscovery = S3EncryptionClient.builder()
          .keyring(kmsDiscoveryKeyring)
          .build();

        ResponseBytes<GetObjectResponse> objectResponse = v3ClientDiscovery.getObjectAsBytes(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .overrideConfiguration(withAdditionalConfiguration(encryptionContext)));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }
}
