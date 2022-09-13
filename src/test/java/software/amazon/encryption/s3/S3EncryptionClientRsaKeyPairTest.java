package software.amazon.encryption.s3;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class S3EncryptionClientRsaKeyPairTest {
    private static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");

    private static KeyPair RSA_KEY_PAIR;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        RSA_KEY_PAIR = keyPairGen.generateKeyPair();
    }

    @Test
    public void RsaPublicAndPrivateKeys() {
        final String BUCKET_KEY = "rsa-public-and-private";

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
    public void RsaPrivateKeyCanOnlyDecrypt() {
        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        S3Client v3ClientReadOnly = S3EncryptionClient.builder()
                .rsaKeyPair(new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), null))
                .build();

        final String input = "RsaOaepV3toV3";
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(input)
                .build(), RequestBody.fromString(input));

        ResponseBytes<GetObjectResponse> objectResponse = v3ClientReadOnly.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(input));
        String output = objectResponse.asUtf8String();
        assertEquals(input, output);

        assertThrows(S3EncryptionClientException.class, () -> v3ClientReadOnly.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(input)
                .build(), RequestBody.fromString(input)));
    }

    @Test
    public void RsaPublicKeyCanOnlyEncrypt() {
        final String BUCKET_KEY = "rsa-public-key-only";
        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(new PartialRsaKeyPair(null, RSA_KEY_PAIR.getPublic()))
                .build();

        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), RequestBody.fromString(BUCKET_KEY));

        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY)));
    }


}
