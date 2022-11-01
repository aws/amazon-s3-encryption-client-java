package software.amazon.encryption.s3;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.*;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class S3EncryptionClientKmsIdentifierValidationTests {
    private static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");
    private static final String KMS_KEY_ID = System.getenv("AWS_S3EC_TEST_KMS_KEY_ID");
    // This alias must point to the same key as KMS_KEY_ID
    public static final String KMS_KEY_ALIAS = System.getenv("AWS_S3EC_TEST_KMS_KEY_ALIAS");
    private static final Region KMS_REGION = Region.getRegion(Regions.fromName(System.getenv("AWS_REGION")));
    private static final String KMS_KEY_ID_Dummy = "arn:aws:kms:us-west-2:452750982249:key/6c7db579-a16c-48c0-adea-604f6b449758";

    @Test
    public void KmsV1toV3IdtoAlias() {
        final String BUCKET_KEY = "kms-v1-to-v3-2";

        // V1 Client
        EncryptionMaterialsProvider materialsProviderId = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProviderId)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID_Dummy)
                .enableLegacyUnauthenticatedModes(true)
                .build();

        // Asserts
        final String input = "KmsV1toV3";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);

        ResponseBytes<GetObjectResponse> output = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY));
        assertEquals(input, output.asUtf8String());
    }

    @Test
    public void KmsV1toV1Dummy() {
        final String BUCKET_KEY = "kms-v1-to-v1-dummy";

        // V1 Client
        EncryptionMaterialsProvider materialsProviderEncrypt = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);
        EncryptionMaterialsProvider materialsProviderDecrypt = new KMSEncryptionMaterialsProvider("1");

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1ClientEncrypt = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProviderEncrypt)
                .build();

        // V1 Client with Alias
        AmazonS3Encryption v1ClientDecrypt = AmazonS3EncryptionClient.encryptionBuilder()
                .withEncryptionMaterials(materialsProviderDecrypt)
                .withCryptoConfiguration(v1Config)
                .build();

        // Asserts
        final String input = "KmsV1toV1Dummy";
        v1ClientEncrypt.putObject(BUCKET, BUCKET_KEY, input);
        String output = v1ClientDecrypt.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
    }

    @Test
    public void KmsV2toV2AliasToId() {
        final String BUCKET_KEY = "kms-v2-to-v2-alias-to-id";

        // V1 Client
        EncryptionMaterialsProvider materialsProviderId = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);
        EncryptionMaterialsProvider materialsProviderAlias = new KMSEncryptionMaterialsProvider(KMS_KEY_ALIAS);

        CryptoConfigurationV2 v2Config = new CryptoConfigurationV2(CryptoMode.AuthenticatedEncryption)
                .withAwsKmsRegion(KMS_REGION);
        // V2 Client For ID
        AmazonS3EncryptionV2 v2ClientId = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProviderId)
                .withCryptoConfiguration(v2Config)
                .build();

        // V2 Client For Alias
        AmazonS3EncryptionV2 v2ClientAlias = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProviderAlias)
                .withCryptoConfiguration(v2Config)
                .build();

        // Asserts
        final String input = "KmsV2toV2AliasToId";
        v2ClientId.putObject(BUCKET, BUCKET_KEY, input);
        String output = v2ClientAlias.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
        v2ClientAlias.putObject(BUCKET, BUCKET_KEY, input);
        output = v2ClientId.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
        // Throws java.lang.IllegalStateException: Provided encryption materials do not match information retrieved from the encrypted object
        //assertThrows(IllegalStateException.class, ()-> v2ClientAlias.getObjectAsString(BUCKET, BUCKET_KEY));
    }

    @Test
    public void KmsV2toV1AliastoId() {
        final String BUCKET_KEY = "kms-v2-to-v1-alias-to-id";

        // V1 Client with Id
        EncryptionMaterialsProvider materialsProviderId = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);
        EncryptionMaterialsProvider materialsProviderAlias = new KMSEncryptionMaterialsProvider(KMS_KEY_ALIAS);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1ClientId = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProviderId)
                .build();

        // V2 Client with Alias
        CryptoConfigurationV2 v2Config = new CryptoConfigurationV2(CryptoMode.AuthenticatedEncryption)
                .withAwsKmsRegion(KMS_REGION);
        AmazonS3EncryptionV2 v2ClientAlias = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProviderAlias)
                .withCryptoConfiguration(v2Config)
                .build();

        // Asserts
        final String input = "KmsV2toV1AliasToId";
        v2ClientAlias.putObject(BUCKET, BUCKET_KEY, input);
        String output = v1ClientId.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
    }

    @Test
    public void KmsV2toV1IdtoAlias() {
        final String BUCKET_KEY = "kms-v2-to-v1-id-to-alias";

        // V1 Client with alias
        EncryptionMaterialsProvider materialsProviderId = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);
        EncryptionMaterialsProvider materialsProviderAlias = new KMSEncryptionMaterialsProvider(KMS_KEY_ALIAS);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1ClientAlias = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProviderAlias)
                .build();

        // V2 Client
        CryptoConfigurationV2 v2Config = new CryptoConfigurationV2(CryptoMode.AuthenticatedEncryption)
                .withAwsKmsRegion(KMS_REGION);
        AmazonS3EncryptionV2 v2ClientId = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProviderId)
                .withCryptoConfiguration(v2Config)
                .build();

        // Asserts
        final String input = "KmsV2toV1IdtoAlias";
        v2ClientId.putObject(BUCKET, BUCKET_KEY, input);
        String output = v1ClientAlias.getObjectAsString(BUCKET, BUCKET_KEY);
        assertEquals(input, output);
    }

    @Test
    public void KmsV1toV2FailsEncryptIdToDecryptAlias() {
        final String BUCKET_KEY = "kms-v1-to-v2-id-to-alias";

        // V1 Client
        EncryptionMaterialsProvider materialsProviderId = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);
        EncryptionMaterialsProvider materialsProviderAlias = new KMSEncryptionMaterialsProvider(KMS_KEY_ALIAS);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1ClientId = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProviderId)
                .build();

        // V2 Client
        CryptoConfigurationV2 v2Config = new CryptoConfigurationV2(CryptoMode.AuthenticatedEncryption)
                .withAwsKmsRegion(KMS_REGION);
        AmazonS3EncryptionV2 v2ClientAlias = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProviderAlias)
                .withCryptoConfiguration(v2Config)
                .build();

        // Asserts
        final String input = "KmsV1toV2IdToAlias";
        v1ClientId.putObject(BUCKET, BUCKET_KEY, input);
        // Throws java.lang.IllegalStateException: Provided encryption materials do not match information retrieved from the encrypted object
        assertThrows(IllegalStateException.class, ()-> v2ClientAlias.getObjectAsString(BUCKET, BUCKET_KEY));
    }

    @Test
    public void KmsV1toV2FailsEncryptAliasToDecryptId() {
        final String BUCKET_KEY = "kms-v1-to-v2-alias-to-id";

        // V1 Client
        EncryptionMaterialsProvider materialsProviderId = new KMSEncryptionMaterialsProvider(KMS_KEY_ID);
        EncryptionMaterialsProvider materialsProviderAlias = new KMSEncryptionMaterialsProvider(KMS_KEY_ALIAS);

        CryptoConfiguration v1Config =
                new CryptoConfiguration(CryptoMode.AuthenticatedEncryption)
                        .withAwsKmsRegion(KMS_REGION);

        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withCryptoConfiguration(v1Config)
                .withEncryptionMaterials(materialsProviderAlias)
                .build();

        // V2 Client
        CryptoConfigurationV2 v2Config = new CryptoConfigurationV2(CryptoMode.AuthenticatedEncryption)
                .withAwsKmsRegion(KMS_REGION);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProviderId)
                .withCryptoConfiguration(v2Config)
                .build();

        // Asserts
        final String input = "KmsV1toV2AliasToId";
        v1Client.putObject(BUCKET, BUCKET_KEY, input);
        // Throws java.lang.IllegalStateException: Provided encryption materials do not match information retrieved from the encrypted object
        assertThrows(IllegalStateException.class, ()-> v2Client.getObjectAsString(BUCKET, BUCKET_KEY));
    }
}
