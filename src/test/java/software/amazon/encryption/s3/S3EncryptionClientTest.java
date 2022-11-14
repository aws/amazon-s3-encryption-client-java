package software.amazon.encryption.s3;

import java.security.SecureRandom;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.materials.AesKeyring;
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
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

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

    @Test
    public void s3EncryptionClientWithNullSecureRandomFails() {
        assertThrows(S3EncryptionClientException.class, () -> S3EncryptionClient.builder()
            .aesKey(AES_KEY)
            .secureRandom(null)
            .build());
    }

    @Test
    public void s3EncryptionClientFromKMSKeyDoesNotUseUnprovidedSecureRandom() {
        SecureRandom mockSecureRandom = mock(SecureRandom.class, withSettings().withoutAnnotations());

        final String objectKey = "no-secure-random-object-kms";

        S3Client v3Client = S3EncryptionClient.builder()
            .kmsKeyId(KMS_KEY_ID)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);

        verify(mockSecureRandom, never()).nextBytes(any());
    }

    @Test
    public void s3EncryptionClientFromKMSKeyIdWithSecureRandomUsesObjectOnceForRoundTripCall() {
        SecureRandom mockSecureRandom = mock(SecureRandom.class, withSettings().withoutAnnotations());

        final String objectKey = "secure-random-object-kms";

        S3Client v3Client = S3EncryptionClient.builder()
            .kmsKeyId(KMS_KEY_ID)
            .secureRandom(mockSecureRandom)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Should only be called from encryption content strategy.
        // KMS keyring does not use SecureRandom for encryptDataKey.
        verify(mockSecureRandom, times(1)).nextBytes(any());
    }

    @Test
    public void s3EncryptionClientFromAESKeyWithSecureRandomUsesObjectTwiceForRoundTripCall() {
        SecureRandom mockSecureRandom = mock(SecureRandom.class, withSettings().withoutAnnotations());

        final String objectKey = "secure-random-object-aes";

        S3Client v3Client = S3EncryptionClient.builder()
            .aesKey(AES_KEY)
            .secureRandom(mockSecureRandom)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Should be called once from encryption content strategy and again from AES encryptDataKey.
        verify(mockSecureRandom, times(2)).nextBytes(any());
    }

    @Test
    public void s3EncryptionClientFromRSAKeyWithSecureRandomUsesObjectTwiceForRoundTripCall() {
        SecureRandom mockSecureRandom = mock(SecureRandom.class, withSettings().withoutAnnotations());

        final String objectKey = "secure-random-object-rsa";

        S3Client v3Client = S3EncryptionClient.builder()
            .rsaKeyPair(RSA_KEY_PAIR)
            .secureRandom(mockSecureRandom)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);

        // Should be called once from encryption content strategy and again from RSA encryptDataKey.
        verify(mockSecureRandom, times(2)).nextBytes(any());
    }

    @Test
    public void s3EncryptionClientFromAESKeyringUsesDifferentSecureRandomThanKeyring() {
        SecureRandom mockSecureRandomKeyring = mock(SecureRandom.class, withSettings().withoutAnnotations());
        SecureRandom mockSecureRandomClient = mock(SecureRandom.class, withSettings().withoutAnnotations());

        AesKeyring keyring = AesKeyring.builder()
            .wrappingKey(AES_KEY)
            .secureRandom(mockSecureRandomKeyring)
            .build();

        final String objectKey = "secure-random-object-aes-different-keyring";

        S3Client v3Client = S3EncryptionClient.builder()
            .keyring(keyring)
            .secureRandom(mockSecureRandomClient)
            .build();

        simpleV3RoundTrip(v3Client, objectKey);

        verify(mockSecureRandomKeyring, times(1)).nextBytes(any());
        verify(mockSecureRandomClient, times(1)).nextBytes(any());
    }

    /**
     * A simple, reusable round-trip (encryption + decryption) using a given
     * S3Client. Useful for testing client configuration.
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
