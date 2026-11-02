package software.amazon.encryption.s3.materials;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.EncryptedPutObjectRequest;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.RetryingTest;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.CommitmentPolicy;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class KmsDiscoveryKeyringTest {
    private static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");
    private static final String KMS_KEY_ID = System.getenv("AWS_S3EC_TEST_KMS_KEY_ID");
    private static final Region KMS_REGION = Region.getRegion(Regions.fromName(System.getenv("AWS_REGION")));

    @RetryingTest(3)
    public void buildKmsDiscoveryKeyringWithNullSecureRandomFails() {
      assertThrows(S3EncryptionClientException.class, () -> KmsDiscoveryKeyring.builder().secureRandom(null));
    }

    @RetryingTest(3)
    public void buildDiscoveryKeyringWithNullDataKeyGeneratorFails() {
      assertThrows(S3EncryptionClientException.class, () -> KmsDiscoveryKeyring.builder().dataKeyGenerator(null));
    }

    @RetryingTest(3)
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
        S3Client s3Client = S3EncryptionClient.builderV4()
                .keyring(kmsDiscoveryKeyring)
                .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
                .build();

        // Asserts
        final String input = "KMS Discovery Keyring";
        v1Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @RetryingTest(3)
    public void testKmsContextV2Discovery() {
        final String objectKey = appendTestSuffix("kms-context-v2-to-v3-discovery");

        // V2 Client
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
          .withEncryptionMaterialsProvider(materialsProvider)
          .build();

        // V3 Client
        KmsDiscoveryKeyring kmsDiscoveryKeyring = KmsDiscoveryKeyring
          .builder().enableLegacyWrappingAlgorithms(true).build();
        S3Client s3Client = S3EncryptionClient.builderV4()
          .keyring(kmsDiscoveryKeyring)
          .commitmentPolicy(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
          .build();

        // Asserts
        final String input = "KmsContextV2toV3Discovery";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value");
        EncryptedPutObjectRequest putObjectRequest = new EncryptedPutObjectRequest(
          BUCKET,
          objectKey,
          new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)),
          null
        ).withMaterialsDescription(encryptionContext);
        v2Client.putObject(putObjectRequest);

        ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .overrideConfiguration(withAdditionalConfiguration(encryptionContext)));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @RetryingTest(3)
    public void testKmsContextV3Discovery() {
        final String objectKey = appendTestSuffix("kms-v3-to-v3-discovery-context");

        // V3 Client - KmsKeyring
        S3Client s3Client = S3EncryptionClient.builderV4()
          .kmsKeyId(KMS_KEY_ID)
          .build();

        final String input = "KmsContextV3toV3Discovery";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3-context");

        s3Client.putObject(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .overrideConfiguration(withAdditionalConfiguration(encryptionContext)), RequestBody.fromString(input));

        // V3 Client - KmsDiscoveryContext
        KmsDiscoveryKeyring kmsDiscoveryKeyring = KmsDiscoveryKeyring
          .builder().enableLegacyWrappingAlgorithms(true).build();
        S3Client s3ClientDiscovery = S3EncryptionClient.builderV4()
          .keyring(kmsDiscoveryKeyring)
          .build();

        ResponseBytes<GetObjectResponse> objectResponse = s3ClientDiscovery.getObjectAsBytes(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .overrideConfiguration(withAdditionalConfiguration(encryptionContext)));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @RetryingTest(3)
    public void testKmsContextV3DiscoveryWrongECFails() {
        final String objectKey = appendTestSuffix("kms-v3-to-v3-discovery-context-wrong-ec");

        // V3 Client - KmsKeyring
        S3Client s3Client = S3EncryptionClient.builderV4()
          .kmsKeyId(KMS_KEY_ID)
          .build();

        final String input = "KmsContextV3toV3Discovery";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3-context");

        s3Client.putObject(builder -> builder
          .bucket(BUCKET)
          .key(objectKey)
          .overrideConfiguration(withAdditionalConfiguration(encryptionContext)), RequestBody.fromString(input));

        // V3 Client - KmsDiscoveryContext
        KmsDiscoveryKeyring kmsDiscoveryKeyring = KmsDiscoveryKeyring
          .builder().enableLegacyWrappingAlgorithms(true).build();
        S3Client s3ClientDiscovery = S3EncryptionClient.builderV4()
          .keyring(kmsDiscoveryKeyring)
          .build();

        Map<String, String> wrongEncryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3-wrong");
        try {
            s3ClientDiscovery.getObjectAsBytes(builder -> builder
              .bucket(BUCKET)
              .key(objectKey)
              .overrideConfiguration(withAdditionalConfiguration(wrongEncryptionContext)));
            fail();
        } catch (S3EncryptionClientException ex) {
            // expected
            assertTrue(ex.getMessage().contains("Provided encryption context does not match information retrieved from S3"));
        }

        // Cleanup
        deleteObject(BUCKET, objectKey, s3Client);
        s3Client.close();
    }

    @RetryingTest(3)
    public void testKmsContextV3DiscoveryEncryptFails() {
        final String objectKey = appendTestSuffix("kms-v3-to-v3-discovery-context-encrypt-fails");

        // V3 Client - KmsDiscoveryKeyring
        KmsDiscoveryKeyring kmsDiscoveryKeyring = KmsDiscoveryKeyring
          .builder().enableLegacyWrappingAlgorithms(true).build();
        S3Client s3ClientDiscovery = S3EncryptionClient.builderV4()
          .keyring(kmsDiscoveryKeyring)
          .build();

        final String input = "KmsContextV3toV3Discovery";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-v3-to-v3-context");

        try {
            s3ClientDiscovery.putObject(builder -> builder
              .bucket(BUCKET)
              .key(objectKey)
              .overrideConfiguration(withAdditionalConfiguration(encryptionContext)), RequestBody.fromString(input));
            fail("expected exception");
        } catch (S3EncryptionClientException exception) {
            // expected
            assertTrue(exception.getMessage().contains("KmsDiscoveryKeyring does not support EncryptDataKey"));
        }
    }

    // The data key was wrapped for a GCM object, so the KMS-authenticated encryption context carries
    // aws:x-amz-cek-alg = AES/GCM/NoPadding, while the decryption materials select the CBC suite.
    @Test
    public void kmsContextDiscoveryDecryptFailsWhenAuthenticatedCekAlgDoesNotMatchSelectedSuite() {
        Map<String, String> storedEncryptionContext = new HashMap<>();
        storedEncryptionContext.put("kms_cmk_id", "arn:aws:kms:us-west-2:111122223333:key/example");
        storedEncryptionContext.put("aws:x-amz-cek-alg", AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherName());

        KmsClient kmsClient = mock(KmsClient.class);
        when(kmsClient.decrypt(argThat((DecryptRequest request) ->
                storedEncryptionContext.equals(request.encryptionContext()))))
                .thenReturn(DecryptResponse.builder()
                        .plaintext(SdkBytes.fromByteArray(new byte[32]))
                        .build());

        KmsDiscoveryKeyring keyring = KmsDiscoveryKeyring.builder()
                .kmsClient(kmsClient)
                .build();

        DecryptionMaterials materials = DecryptionMaterials.builder()
                .s3Request(GetObjectRequest.builder().bucket("bucket").key("key").build())
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF)
                .encryptionContext(storedEncryptionContext)
                .build();

        EncryptedDataKey edk = EncryptedDataKey.builder()
                .keyProviderId(S3Keyring.KEY_PROVIDER_ID)
                .keyProviderInfo("kms+context")
                .encryptedDataKey(new byte[]{1, 2, 3})
                .build();

        assertThrows(S3EncryptionClientException.class,
                () -> keyring.onDecrypt(materials, Collections.singletonList(edk)));
    }

}
