package software.amazon.encryption.s3;

import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.CryptoConfigurationV2;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.CryptoStorageMode;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DefaultCryptoMaterialsManager;
import software.amazon.encryption.s3.materials.KmsKeyring;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ALIAS;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
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

    //@Test
    public void deleteObjectWithInstructionFileSuccess() {
        final String objectKey = appendTestSuffix("delete-object-with-instruction-file");

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

    //@Test
    public void deleteObjectsWithInstructionFilesSuccess() {
        final String[] objectKeys = {appendTestSuffix("delete-object-with-instruction-file-1"),
                appendTestSuffix("delete-object-with-instruction-file-2"),
                appendTestSuffix("delete-object-with-instruction-file-3")};

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
            v2Client.putObject(BUCKET, appendTestSuffix(objectKey), input);
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

    //@Test
    public void deleteObjectWithWrongObjectKeySuccess() {
        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        assertDoesNotThrow(() -> v3Client.deleteObject(builder -> builder.bucket(BUCKET).key("InvalidKey")));

        // Cleanup
        v3Client.close();
    }

    //@Test
    public void s3EncryptionClientWithMultipleKeyringsFails() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .rsaKeyPair(RSA_KEY_PAIR)
                .build());
    }

    //@Test
    public void s3EncryptionClientWithNoKeyringsFails() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .build());
    }

    //@Test
    public void s3EncryptionClientWithNoLegacyKeyringsFails() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .enableLegacyUnauthenticatedModes(true)
                .build());
    }

    //@Test
    public void KmsWithAliasARN() {
        final String objectKey = appendTestSuffix("kms-with-alias-arn");
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ALIAS)
                .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void KmsWithShortKeyId() {
        final String objectKey = appendTestSuffix("kms-with-short-key-id");
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

    //@Test
    public void KmsAliasARNToKeyId() {
        final String objectKey = appendTestSuffix("kms-alias-arn-to-key-id");
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
                        .overrideConfiguration(withAdditionalConfiguration(encryptionContext)),
                RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = keyIdClient.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .overrideConfiguration(withAdditionalConfiguration(encryptionContext)));
        String output = objectResponse.asUtf8String();

        assertEquals(input, output);
        deleteObject(BUCKET, objectKey, aliasClient);
        aliasClient.close();
        keyIdClient.close();
    }

    //@Test
    public void AesKeyringWithInvalidAesKey() throws NoSuchAlgorithmException {
        SecretKey invalidAesKey;
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        invalidAesKey = keyGen.generateKey();

        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .aesKey(invalidAesKey)
                .build());
    }

    //@Test
    public void RsaKeyringWithInvalidRsaKey() throws NoSuchAlgorithmException {
        KeyPair invalidRsaKey;
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256);
        invalidRsaKey = keyPairGen.generateKeyPair();

        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
                .rsaKeyPair(invalidRsaKey)
                .build());
    }

    //@Test
    public void s3EncryptionClientWithKeyringFromKmsKeyIdSucceeds() {
        final String objectKey = appendTestSuffix("keyring-from-kms-key-id");

        KmsKeyring keyring = KmsKeyring.builder().wrappingKeyId(KMS_KEY_ID).build();

        S3Client v3Client = S3EncryptionClient.builder()
            .keyring(keyring)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void s3EncryptionClientWithCmmFromKmsKeyIdSucceeds() {
        final String objectKey = appendTestSuffix("cmm-from-kms-key-id");

        KmsKeyring keyring = KmsKeyring.builder().wrappingKeyId(KMS_KEY_ID).build();

        CryptographicMaterialsManager cmm = DefaultCryptoMaterialsManager.builder()
            .keyring(keyring)
            .build();

        S3Client v3Client = S3EncryptionClient.builder()
            .cryptoMaterialsManager(cmm)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void s3EncryptionClientWithWrappedS3ClientSucceeds() {
        final String objectKey = appendTestSuffix("wrapped-s3-client-with-kms-key-id");

        S3Client wrappedClient = S3Client.builder().build();

        S3Client wrappingClient = S3EncryptionClient.builder()
            .wrappedClient(wrappedClient)
            .kmsKeyId(KMS_KEY_ID)
            .build();

        simpleV3RoundTrip(wrappingClient, objectKey);

        // Cleanup
        deleteObject(BUCKET, objectKey, wrappingClient);
        wrappedClient.close();
        wrappingClient.close();
    }

    /**
     * S3EncryptionClient implements S3Client, so it can be passed into the builder as a wrappedClient.
     * However, is not a supported use case, and the builder should throw an exception if this happens.
     */
    //@Test
    public void s3EncryptionClientWithWrappedS3EncryptionClientFails() {
        S3Client wrappedClient = S3EncryptionClient.builder()
            .kmsKeyId(KMS_KEY_ID)
            .build();

        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
            .wrappedClient(wrappedClient)
            .kmsKeyId(KMS_KEY_ID)
            .build());
    }

    //@Test
    public void s3EncryptionClientWithNullSecureRandomFails() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
            .aesKey(AES_KEY)
            .secureRandom(null)
            .build());
    }

    //@Test
    public void s3EncryptionClientFromKMSKeyDoesNotUseUnprovidedSecureRandom() {
        SecureRandom mockSecureRandom = mock(SecureRandom.class, withSettings().withoutAnnotations());

        final String objectKey = appendTestSuffix("no-secure-random-object-kms");

        S3Client v3Client = S3EncryptionClient.builder()
            .kmsKeyId(KMS_KEY_ID)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);

        verify(mockSecureRandom, never()).nextBytes(any());

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void s3EncryptionClientFromKMSKeyIdWithSecureRandomUsesObjectOnceForRoundTripCall() {
        SecureRandom mockSecureRandom = mock(SecureRandom.class, withSettings().withoutAnnotations());

        final String objectKey = appendTestSuffix("secure-random-object-kms");

        S3Client v3Client = S3EncryptionClient.builder()
            .kmsKeyId(KMS_KEY_ID)
            .secureRandom(mockSecureRandom)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Should only be called from encryption content strategy.
        // KMS keyring does not use SecureRandom for encryptDataKey.
        verify(mockSecureRandom, times(1)).nextBytes(any());

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void s3EncryptionClientFromAESKeyWithSecureRandomUsesObjectTwiceForRoundTripCall() {
        SecureRandom mockSecureRandom = mock(SecureRandom.class, withSettings().withoutAnnotations());

        final String objectKey = appendTestSuffix("secure-random-object-aes");

        S3Client v3Client = S3EncryptionClient.builder()
            .aesKey(AES_KEY)
            .secureRandom(mockSecureRandom)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Should be called once from encryption content strategy and again from AES encryptDataKey.
        verify(mockSecureRandom, times(2)).nextBytes(any());

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void s3EncryptionClientFromRSAKeyWithSecureRandomUsesObjectTwiceForRoundTripCall() {
        SecureRandom mockSecureRandom = mock(SecureRandom.class, withSettings().withoutAnnotations());

        final String objectKey = appendTestSuffix("secure-random-object-rsa");

        S3Client v3Client = S3EncryptionClient.builder()
            .rsaKeyPair(RSA_KEY_PAIR)
            .secureRandom(mockSecureRandom)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Should be called once from encryption content strategy and again from RSA encryptDataKey.
        verify(mockSecureRandom, times(2)).nextBytes(any());

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void s3EncryptionClientFromAESKeyringUsesDifferentSecureRandomThanKeyring() {
        SecureRandom mockSecureRandomKeyring = mock(SecureRandom.class, withSettings().withoutAnnotations());
        SecureRandom mockSecureRandomClient = mock(SecureRandom.class, withSettings().withoutAnnotations());

        AesKeyring keyring = AesKeyring.builder()
            .wrappingKey(AES_KEY)
            .secureRandom(mockSecureRandomKeyring)
            .build();

        final String objectKey = appendTestSuffix("secure-random-object-aes-different-keyring");

        S3Client v3Client = S3EncryptionClient.builder()
            .keyring(keyring)
            .secureRandom(mockSecureRandomClient)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);

        verify(mockSecureRandomKeyring, times(1)).nextBytes(any());
        verify(mockSecureRandomClient, times(1)).nextBytes(any());

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
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

    //@Test
    public void cryptoProviderV3toV3Enabled() {
        final String objectKey = appendTestSuffix("crypto-provider-enabled-v3-to-v3");

        Security.addProvider(new BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .cryptoProvider(provider)
                .build();

        final String input = "CryptoProviderEnabled";
        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void cryptoProviderV2toV3Enabled() {
        final String objectKey = appendTestSuffix("crypto-provider-enabled-v2-to-v3");

        Security.addProvider(new BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");

        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfigurationV2 v2Config = new CryptoConfigurationV2()
                .withCryptoProvider(provider)
                .withAlwaysUseCryptoProvider(true);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .withCryptoConfiguration(v2Config)
                .build();

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .cryptoProvider(provider)
                .build();

        final String input = "CryptoProviderEnabled";
        v2Client.putObject(BUCKET, objectKey, input);

        ResponseBytes<GetObjectResponse> objectResponse = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }
}
