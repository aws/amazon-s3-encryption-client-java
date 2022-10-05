package software.amazon.encryption.s3;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class S3EncryptionClientStreamTest {

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
    public void AesGcmV2toV2StreamWithTamperedTag() {
        final String BUCKET_KEY = "aes-gcm-v2-to-v2-stream";

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // 640 bytes of gibberish - enough to cover multiple blocks
        final String input = "1esGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYo"
                + "2esGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYo"
                + "3esGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYo"
                + "4esGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYo"
                + "5esGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYo"
                + "6esGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYo"
                + "7esGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYo"
                + "8esGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYo"
                + "9esGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYo"
                + "10sGcmYoAesGcmEndOfChunkAesGcmYoAesGcmYoAesGcmYoAesGcmYoAesGcmYo";
        final int inputLength = input.length();
        v2Client.putObject(BUCKET, BUCKET_KEY, input);

        // Use an unencrypted (plaintext) client to interact with the encrypted object
        final S3Client plaintextS3Client = S3Client.builder().build();
        ResponseBytes<GetObjectResponse> objectResponse = plaintextS3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY));
        final byte[] encryptedBytes = objectResponse.asByteArray();
        final int tagLength = 16;
        final byte[] tamperedBytes = new byte[inputLength + tagLength];
        // Copy the enciphered bytes
        System.arraycopy(encryptedBytes, 0, tamperedBytes, 0, inputLength);
        final byte[] tamperedTag = new byte[tagLength];
        // Increment the first byte of the tag
        tamperedTag[0] = (byte) (encryptedBytes[inputLength + 1] + 1);
        // Copy the rest of the tag as-is
        System.arraycopy(encryptedBytes, inputLength + 1, tamperedTag, 1, tagLength - 1);
        // Append the tampered tag
        System.arraycopy(tamperedTag, 0, tamperedBytes, inputLength, tagLength);

        // Sanity check that the objects differ
        assertNotEquals(encryptedBytes, tamperedBytes);

        // Replace the encrypted object with the tampered object
        PutObjectRequest tamperedPut = PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .metadata(objectResponse.response().metadata()) // Preserve metadata from encrypted object
                .build();
        plaintextS3Client.putObject(tamperedPut, RequestBody.fromBytes(tamperedBytes));

        // Get (and decrypt) the (modified) object from S3
        final S3Object s3Object = v2Client.getObject(BUCKET, BUCKET_KEY);

        // Use a few different byte arrays to demonstrate streaming
        final int chunkSize = 300;
        final int leftOverSize = inputLength - 2 * chunkSize;
        final byte[] chunk1 = new byte[chunkSize];
        final byte[] chunk2 = new byte[chunkSize];
        final byte[] restOfInput = new byte[leftOverSize];

        try (final InputStream dataStream = s3Object.getObjectContent()) {
            dataStream.read(chunk1, 0, chunkSize);
            dataStream.read(chunk2, 0, chunkSize);
            System.out.println("So far we have: " + new String(chunk1) + new String(chunk2));
            dataStream.read(restOfInput, 0, leftOverSize);
        } catch (final IOException ioException) {
            // Just wrap the checked exception so test fails
            throw new RuntimeException(ioException);
        }

        // Should be a StringBuilder, oh well, we shouldn't get this far
        final String readOutput = new String(chunk1) + new String(chunk2) + new String(restOfInput);
        assertEquals(input, readOutput);
    }
}
