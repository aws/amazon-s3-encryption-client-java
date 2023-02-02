package software.amazon.encryption.s3;

import com.amazonaws.services.s3.AmazonS3Encryption;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.CryptoMode;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.utils.BoundedStreamBufferer;
import software.amazon.encryption.s3.utils.BoundedZerosInputStream;
import software.amazon.encryption.s3.utils.MarkResetBoundedZerosInputStream;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

/**
 * Test the streaming functionality using various stream implementations.
 */
public class S3EncryptionClientStreamTest {

    private static final String BUCKET = S3EncryptionClientTestResources.BUCKET;
    private static final int DEFAULT_TEST_STREAM_LENGTH = (int) (Math.random() * 10000);

    private static SecretKey AES_KEY;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();
    }

    //@Test
    public void markResetInputStreamV3Encrypt() throws IOException {
        final String objectKey = appendTestSuffix("markResetInputStreamV3Encrypt");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        final int inputLength = DEFAULT_TEST_STREAM_LENGTH;
        final InputStream inputStream = new MarkResetBoundedZerosInputStream(inputLength);
        inputStream.mark(inputLength);
        final String inputStreamAsUtf8String = IoUtils.toUtf8String(inputStream);
        inputStream.reset();

        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromInputStream(inputStream, inputLength));
        inputStream.close();

        final String actualObject = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build()).asUtf8String();

        assertEquals(inputStreamAsUtf8String, actualObject);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void ordinaryInputStreamV3Encrypt() throws IOException {
        final String objectKey = appendTestSuffix("ordinaryInputStreamV3Encrypt");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        final int inputLength = DEFAULT_TEST_STREAM_LENGTH;
        // Create a second stream of zeros because reset is not supported
        // and reading into the byte string will consume the stream.
        final InputStream inputStream = new BoundedZerosInputStream(inputLength);
        final InputStream inputStreamForString = new BoundedZerosInputStream(inputLength);
        final String inputStreamAsUtf8String = IoUtils.toUtf8String(inputStreamForString);

        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromInputStream(inputStream, inputLength));
        inputStream.close();

        final String actualObject = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build()).asUtf8String();

        assertEquals(inputStreamAsUtf8String, actualObject);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void ordinaryInputStreamV3Decrypt() throws IOException {
        final String objectKey = appendTestSuffix("ordinaryInputStreamV3Decrypt");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        final int inputLength = DEFAULT_TEST_STREAM_LENGTH;
        // Create a second stream of zeros because reset is not supported
        // and reading into the byte string will consume the stream.
        final InputStream inputStream = new BoundedZerosInputStream(inputLength);
        final InputStream inputStreamForString = new BoundedZerosInputStream(inputLength);
        final String inputStreamAsUtf8String = IoUtils.toUtf8String(inputStreamForString);

        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromInputStream(inputStream, inputLength));
        inputStream.close();

        final ResponseInputStream<GetObjectResponse> responseInputStream = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());
        final String actualObject = new String(BoundedStreamBufferer.toByteArray(responseInputStream, inputLength / 8),
                StandardCharsets.UTF_8);

        assertEquals(inputStreamAsUtf8String, actualObject);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void markResetInputStreamV3DecryptGcm() throws IOException {
        final String objectKey = appendTestSuffix("markResetInputStreamV3DecryptGcm");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        final int inputLength = DEFAULT_TEST_STREAM_LENGTH;
        // Create a second stream of zeros because reset is not supported
        // and reading into the byte string will consume the stream.
        final InputStream inputStream = new BoundedZerosInputStream(inputLength);
        final InputStream inputStreamForString = new BoundedZerosInputStream(inputLength);
        final String inputStreamAsUtf8String = IoUtils.toUtf8String(inputStreamForString);

        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromInputStream(inputStream, inputLength));
        inputStream.close();

        final ResponseInputStream<GetObjectResponse> responseInputStream = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());
        final String actualObject = new String(BoundedStreamBufferer.toByteArrayWithMarkReset(responseInputStream, inputLength / 8),
                StandardCharsets.UTF_8);

        assertEquals(inputStreamAsUtf8String, actualObject);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void ordinaryInputStreamV3DecryptCbc() throws IOException {
        final String objectKey = appendTestSuffix("markResetInputStreamV3DecryptCbc");

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

        final int inputLength = DEFAULT_TEST_STREAM_LENGTH;
        final InputStream inputStreamForString = new BoundedZerosInputStream(inputLength);
        final String inputStreamAsUtf8String = IoUtils.toUtf8String(inputStreamForString);

        v1Client.putObject(BUCKET, objectKey, inputStreamAsUtf8String);

        final ResponseInputStream<GetObjectResponse> responseInputStream = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)
                .build());
        final String actualObject = new String(BoundedStreamBufferer.toByteArray(responseInputStream, inputLength / 8),
                StandardCharsets.UTF_8);

        assertEquals(inputStreamAsUtf8String, actualObject);

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void delayedAuthModeWithLargeObject() throws IOException {
        final String objectKey = appendTestSuffix("large-object-test");

        Security.addProvider(new BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .cryptoProvider(provider)
                .build();

        // Tight bound on the default limit of 64MiB
        final long fileSizeExceedingDefaultLimit = 1024 * 1024 * 64 + 1;
        final InputStream largeObjectStream = new BoundedZerosInputStream(fileSizeExceedingDefaultLimit);
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromInputStream(largeObjectStream, fileSizeExceedingDefaultLimit));

        largeObjectStream.close();

        // Delayed Authentication is not enabled, so getObject fails
        assertThrows(S3EncryptionClientException.class, () -> v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey)));
                
        S3Client v3ClientWithDelayedAuth = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableDelayedAuthenticationMode(true)
                .build();

        // Once enabled, the getObject request passes
        v3ClientWithDelayedAuth.getObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));

        // Cleanup
        deleteObject(BUCKET, objectKey, v3Client);
        v3Client.close();
    }

    //@Test
    public void delayedAuthModeWithLargerThanMaxObjectFails() throws IOException {
        final String objectKey = appendTestSuffix("larger-than-max-object-delayed-auth-mode");

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableDelayedAuthenticationMode(true)
                .build();

        final long fileSizeExceedingGCMLimit = (1L << 39) - 256 / 8;
        final InputStream largeObjectStream = new BoundedZerosInputStream(fileSizeExceedingGCMLimit);
        assertThrows(S3EncryptionClientException.class, () -> v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(objectKey)
                .build(), RequestBody.fromInputStream(largeObjectStream, fileSizeExceedingGCMLimit)));

        largeObjectStream.close();

        // Cleanup
        v3Client.close();
    }
}
