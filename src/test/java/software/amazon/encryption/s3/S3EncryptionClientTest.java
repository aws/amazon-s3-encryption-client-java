package software.amazon.encryption.s3;

import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.CryptoConfigurationV2;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DefaultCryptoMaterialsManager;
import software.amazon.encryption.s3.materials.KmsKeyring;
import software.amazon.encryption.s3.utils.BoundedZerosInputStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalEncryptionContext;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ALIAS;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

/**
 * This class is an integration test for verifying behavior of the V3 client
 * under various scenarios.
 */
public class S3EncryptionClientTest {

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
    public void deleteObjectWithInstructionFileSuccess() {
        final String objectKey = "delete-object-with-instruction-file";

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
        final String input = "DeleteObjectWithInstructionFileSuccess";
        v2Client.putObject(BUCKET, objectKey, input);

        // Delete Object
        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));

        S3Client s3Client = S3Client.builder().build();
        // Assert throw NoSuchKeyException when getObject for objectKey
        assertThrows(S3Exception.class, () -> s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));
        assertThrows(S3Exception.class, () -> s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey + ".instruction")));

        // Cleanup
        v3Client.close();
        s3Client.close();
    }

    @Test
    public void deleteObjectsWithInstructionFilesSuccess() {
        final String[] objectKeys = {"delete-object-with-instruction-file-1",
                "delete-object-with-instruction-file-2",
                "delete-object-with-instruction-file-3"};

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
        final String input = "DeleteObjectsWithInstructionFileSuccess";
        List<ObjectIdentifier> objects = new ArrayList<>();
        for (String objectKey : objectKeys) {
            v2Client.putObject(BUCKET, objectKey, input);
            objects.add(ObjectIdentifier.builder().key(objectKey).build());
        }

        // Delete Objects from S3 Buckets
        v3Client.deleteObjects(builder -> builder
                .bucket(BUCKET)
                .delete(builder1 -> builder1.objects(objects)));

        S3Client s3Client = S3Client.builder().build();
        // Assert throw NoSuchKeyException when getObject for any of objectKeys
        assertThrows(S3Exception.class, () -> s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKeys[0])));
        assertThrows(S3Exception.class, () -> s3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKeys[0] + ".instruction")));

        // Cleanup
        v3Client.close();
        s3Client.close();
    }

    @Test
    public void deleteObjectWithWrongObjectKeySuccess() {
        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        assertDoesNotThrow(() -> v3Client.deleteObject(builder -> builder.bucket(BUCKET).key("InvalidKey")));

        // Cleanup
        v3Client.close();
    }

    @Test
    public void s3EncryptionClientWithMultipleKeyringsFails() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .rsaKeyPair(RSA_KEY_PAIR)
                .build());
    }

    @Test
    public void s3EncryptionClientWithNoKeyringsFails() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .build());
    }

    @Test
    public void s3EncryptionClientWithNoLegacyKeyringsFails() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .enableLegacyUnauthenticatedModes(true)
                .build());
    }

    @Test
    public void KmsWithAliasARN() {
        final String objectKey = "kms-with-alias-arn";
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ALIAS)
                .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void KmsWithShortKeyId() {
        final String objectKey = "kms-with-short-key-id";
        // Just assume the ARN is well-formed
        // Also assume that the region is set correctly
        final String shortId = KMS_KEY_ID.split("/")[1];

        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(shortId)
                .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void KmsAliasARNToKeyId() {
        final String objectKey = "kms-alias-arn-to-key-id";
        S3Client aliasClient = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ALIAS)
                .build();

        S3Client keyIdClient = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        final String input = "KmsAliasARNToKeyId";
        Map<String, String> encryptionContext = new HashMap<>();
        encryptionContext.put("user-metadata-key", "user-metadata-value-alias-to-id");

        aliasClient.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .overrideConfiguration(withAdditionalEncryptionContext(encryptionContext)),
                RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = keyIdClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalEncryptionContext(encryptionContext)));
        String output = objectResponse.asUtf8String();

        assertEquals(input, output);
        deleteObject(BUCKET, objectKey, aliasClient);
        aliasClient.close();
        keyIdClient.close();
    }

    @Test
    public void AesKeyringWithInvalidAesKey() throws NoSuchAlgorithmException {
        SecretKey invalidAesKey;
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        invalidAesKey = keyGen.generateKey();

        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .aesKey(invalidAesKey)
                .build());
    }

    @Test
    public void RsaKeyringWithInvalidRsaKey() throws NoSuchAlgorithmException {
        KeyPair invalidRsaKey;
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256);
        invalidRsaKey = keyPairGen.generateKeyPair();

        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .rsaKeyPair(invalidRsaKey)
                .build());
    }

    @Test
    public void defaultModeWithLargeObjectFails() throws IOException {
        final String objectKey = "large-object";

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Tight bound on the default limit of 64MiB
        final long fileSizeExceedingDefaultLimit = 1024 * 1024 * 64 + 1;
        final InputStream largeObjectStream = new BoundedZerosInputStream(fileSizeExceedingDefaultLimit);
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromInputStream(largeObjectStream, fileSizeExceedingDefaultLimit));

        largeObjectStream.close();

        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));


        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }


    @Test
    public void s3EncryptionClientWithKeyringFromKmsKeyIdSucceeds() {
        final String objectKey = "keyring-from-kms-key-id";

        KmsKeyring keyring = KmsKeyring.builder().wrappingKeyId(KMS_KEY_ID).build();

        S3Client v3Client = S3EncryptionClient.builder()
            .keyring(keyring)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);
    }

    @Test
    public void s3EncryptionClientWithCmmFromKmsKeyIdSucceeds() {
        final String objectKey = "cmm-from-kms-key-id";

        KmsKeyring keyring = KmsKeyring.builder().wrappingKeyId(KMS_KEY_ID).build();

        CryptographicMaterialsManager cmm = DefaultCryptoMaterialsManager.builder()
            .keyring(keyring)
            .build();

        S3Client v3Client = S3EncryptionClient.builder()
            .cryptoMaterialsManager(cmm)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);
    }

    @Test
    public void s3EncryptionClientWithWrappedS3ClientSucceeds() {
        final String objectKey = "wrapped-s3-client-with-kms-key-id";

        S3Client wrappedClient = S3Client.builder().build();

        S3Client wrappingClient = S3EncryptionClient.builder()
            .wrappedClient(wrappedClient)
            .kmsKeyId(KMS_KEY_ID)
            .build();

        simpleV3RoundTrip(wrappingClient, objectKey);
    }

    /**
     * S3EncryptionClient implements S3Client, so it can be passed into the builder as a wrappedClient.
     * However, is not a supported use case, and the builder should throw an exception if this happens.
     */
    @Test
    public void s3EncryptionClientWithWrappedS3EncryptionClientFails() {
        S3Client wrappedClient = S3EncryptionClient.builder()
            .kmsKeyId(KMS_KEY_ID)
            .build();

        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
            .wrappedClient(wrappedClient)
            .kmsKeyId(KMS_KEY_ID)
            .build());
    }

    /**
     * A simple, reusable round-trip (encryption + decryption) using a given
     * S3Client. Useful for testing client configuration.
     *
     * @param v3Client the client under test
     */
    private void simpleV3RoundTrip(final S3Client v3Client, final String objectKey) {
        final String input = "SimpleTestOfV3EncryptionClient";

        v3Client.putObject(builder -> builder
                        .bucket(BUCKET)
                        .key(objectKey)
                        .build(),
                RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);
    }
}
