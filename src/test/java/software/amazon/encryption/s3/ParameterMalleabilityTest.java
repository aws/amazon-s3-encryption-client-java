package software.amazon.encryption.s3;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class ParameterMalleabilityTest {

    private static SecretKey AES_KEY;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();
    }

    @Test
    public void contentEncryptionDowngradeAttackFails() {
        final String objectKey = appendTestSuffix("content-downgrade-attack-fails");
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        final String input = "ContentDowngradeAttackFails";

        // Encrypt something using AES-GCM
        v3Client.putObject(builder -> builder.bucket(BUCKET).key(objectKey), RequestBody.fromString(input));

        // Using a default client, tamper with the metadata
        // CBC mode uses no parameter value, so just remove the "cek-alg" key
        S3Client defaultClient = S3Client.builder().build();
        ResponseInputStream<GetObjectResponse> response = defaultClient.getObject(builder -> builder.bucket(BUCKET).key(objectKey));
        final Map<String, String> objectMetadata = response.response().metadata();
        final Map<String, String> tamperedMetadata = new HashMap<>(objectMetadata);
        tamperedMetadata.remove("x-amz-cek-alg");

        // Replace the object with the content encryption algorithm removed
        defaultClient.putObject(builder -> builder.bucket(BUCKET).key(objectKey).metadata(tamperedMetadata),
                RequestBody.fromInputStream(response, response.response().contentLength()));

        // getObject fails
        assertThrows(Exception.class, () -> v3Client.getObject(builder -> builder.bucket(BUCKET).key(objectKey)));

        // Enabling unauthenticated modes also fail
        S3Client v3ClientUnauthenticated = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyUnauthenticatedModes(true)
                .enableLegacyWrappingAlgorithms(true)
                .build();
        assertThrows(Exception.class, () -> v3ClientUnauthenticated.getObject(builder -> builder.bucket(BUCKET).key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void keyWrapRemovalAttackFails() {
        final String objectKey = appendTestSuffix("keywrap-removal-attack-fails");
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        final String input = "KeyWrapRemovalAttackFails";

        // Encrypt something using AES-GCM
        v3Client.putObject(builder -> builder.bucket(BUCKET).key(objectKey), RequestBody.fromString(input));

        // Using a default client, tamper with the metadata
        S3Client defaultClient = S3Client.builder().build();
        ResponseInputStream<GetObjectResponse> response = defaultClient.getObject(builder -> builder.bucket(BUCKET).key(objectKey));
        final Map<String, String> objectMetadata = response.response().metadata();
        final Map<String, String> tamperedMetadata = new HashMap<>(objectMetadata);
        tamperedMetadata.remove("x-amz-wrap-alg");

        // Replace the object
        defaultClient.putObject(builder -> builder.bucket(BUCKET).key(objectKey).metadata(tamperedMetadata),
                RequestBody.fromInputStream(response, response.response().contentLength()));

        // getObject fails
        assertThrows(Exception.class, () -> v3Client.getObject(builder -> builder.bucket(BUCKET).key(objectKey)));

        // Enabling unauthenticated modes also fail
        S3Client v3ClientUnauthenticated = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyUnauthenticatedModes(true)
                .enableLegacyWrappingAlgorithms(true)
                .build();
        assertThrows(Exception.class, () -> v3ClientUnauthenticated.getObject(builder -> builder.bucket(BUCKET).key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void keyWrapDowngradeAesWrapAttackFails() {
        final String objectKey = appendTestSuffix("keywrap-downgrade-aeswrap-attack-fails");
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        final String input = "KeyWrapDowngradeAesWrapAttackFails";

        // Encrypt something using AES-GCM
        v3Client.putObject(builder -> builder.bucket(BUCKET).key(objectKey), RequestBody.fromString(input));

        // Using a default client, tamper with the metadata
        S3Client defaultClient = S3Client.builder().build();
        ResponseInputStream<GetObjectResponse> response = defaultClient.getObject(builder -> builder.bucket(BUCKET).key(objectKey));
        final Map<String, String> objectMetadata = response.response().metadata();
        final Map<String, String> tamperedMetadata = new HashMap<>(objectMetadata);
        // Replace wrap-alg with AESWrap
        tamperedMetadata.put("x-amz-wrap-alg", "AESWrap");

        // Replace the object
        defaultClient.putObject(builder -> builder.bucket(BUCKET).key(objectKey).metadata(tamperedMetadata),
                RequestBody.fromInputStream(response, response.response().contentLength()));

        // getObject fails
        assertThrows(Exception.class, () -> v3Client.getObject(builder -> builder.bucket(BUCKET).key(objectKey)));

        // Enabling unauthenticated modes also fail
        S3Client v3ClientUnauthenticated = S3EncryptionClient.builder()
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(true)
                .aesKey(AES_KEY)
                .build();
        assertThrows(Exception.class, () -> v3ClientUnauthenticated.getObject(builder -> builder.bucket(BUCKET).key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    @Test
    public void keyWrapDowngradeAesAttackFails() {
        final String objectKey = appendTestSuffix("keywrap-downgrade-aes-attack-fails");
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();
        final String input = "KeyWrapDowngradeAesAttackFails";

        // Encrypt something using AES-GCM
        v3Client.putObject(builder -> builder.bucket(BUCKET).key(objectKey), RequestBody.fromString(input));

        // Using a default client, tamper with the metadata
        S3Client defaultClient = S3Client.builder().build();
        ResponseInputStream<GetObjectResponse> response = defaultClient.getObject(builder -> builder.bucket(BUCKET).key(objectKey));
        final Map<String, String> objectMetadata = response.response().metadata();
        final Map<String, String> tamperedMetadata = new HashMap<>(objectMetadata);
        // Replace wrap-alg with AES
        tamperedMetadata.put("x-amz-wrap-alg", "AES");

        // Replace the object
        defaultClient.putObject(builder -> builder.bucket(BUCKET).key(objectKey).metadata(tamperedMetadata),
                RequestBody.fromInputStream(response, response.response().contentLength()));

        // getObject fails
        assertThrows(Exception.class, () -> v3Client.getObject(builder -> builder.bucket(BUCKET).key(objectKey)));

        // Enabling unauthenticated modes also fail
        S3Client v3ClientUnauthenticated = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableLegacyWrappingAlgorithms(true)
                .enableLegacyUnauthenticatedModes(true)
                .build();
        assertThrows(Exception.class, () -> v3ClientUnauthenticated.getObject(builder -> builder.bucket(BUCKET).key(objectKey)));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }


}
