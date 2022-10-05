package software.amazon.encryption.s3;

import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class S3EncryptionClientStreamTest {

    private static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");

    private static SecretKey AES_KEY;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();
    }

    @Test
    public void AesGcmV2toV2WithTamperedTag() {
        final String BUCKET_KEY = "aes-gcm-v2-to-v2-tamper-tag";

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // 640 bytes of gibberish - enough to cover multiple blocks
        // Not that it necessarily matters, but feels more sane this way
        // TODO: Try a smaller input too.
        final String input = "1esAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFF"
                + "2esAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFF"
                + "3esAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFF"
                + "4esAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFF"
                + "5esAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFF"
                + "6esAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFF"
                + "7esAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFF"
                + "8esAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFF"
                + "9esAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFFtagAesFF"
                + "10sAesFFtagAesEndOfChunktagAesFFtagAesFFtagAesFFtagAesFFtagAesFF";
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
        final String readOutput = v2Client.getObjectAsString(BUCKET, BUCKET_KEY);

        assertEquals(input, readOutput);
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
        // XOR the first byte of the tag
        tamperedTag[0] = (byte) (encryptedBytes[inputLength + 1] ^ 1);
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
            int result = dataStream.read(restOfInput, 0, leftOverSize);
            System.out.println("The result from last read is: " + result);
        } catch (final IOException ioException) {
            // Just wrap the checked exception so test fails
            throw new RuntimeException(ioException);
        }

        // Should be a StringBuilder, oh well, we shouldn't get this far
        final String readOutput = new String(chunk1) + new String(chunk2) + new String(restOfInput);
        assertEquals(input, readOutput);
    }

    @Test
    public void AesGcmV3toV3StreamWithTamperedTag() {
        final String BUCKET_KEY = "aes-gcm-v3-to-v3-stream";

        // V3 Client
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();


        // 640 bytes of gibberish - enough to cover multiple blocks
        final String input = "1esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "2esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "3esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "4esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "5esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "6esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "7esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "8esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "9esAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo"
                + "10sAAAYoAesAAAEndOfChunkAesAAAYoAesAAAYoAesAAAYoAesAAAYoAesAAAYo";
        final int inputLength = input.length();
        v3Client.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), RequestBody.fromString(input));

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
        ResponseInputStream<GetObjectResponse> dataStream = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY));

        // Use a few different byte arrays to demonstrate streaming
        final int chunkSize = 300;
        final int leftOverSize = inputLength - 2 * chunkSize;
        final byte[] chunk1 = new byte[chunkSize];
        final byte[] chunk2 = new byte[chunkSize];
        final byte[] restOfInput = new byte[leftOverSize];

        try {
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

    @Test
    public void AesGcmV2toV2StreamBigRead() {
        final String BUCKET_KEY = "aes-gcm-v2-to-v2-stream-big-read";

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // 640 bytes of gibberish - enough to cover multiple blocks
        final String input = "1esGcmYoReadThisReadThisReadThisReadThisReadThisReadThisReadThis"
                + "2esGcmYoReadThisReadThisReadThisReadThisReadThisReadThisReadThis"
                + "3esGcmYoReadThisReadThisReadThisReadThisReadThisReadThisReadThis"
                + "4esGcmYoReadThisReadThisReadThisReadThisReadThisReadThisReadThis"
                + "5esGcmYoReadThisReadThisReadThisReadThisReadThisReadThisReadThis"
                + "6esGcmYoReadThisReadThisReadThisReadThisReadThisReadThisReadThis"
                + "7esGcmYoReadThisReadThisReadThisReadThisReadThisReadThisReadThis"
                + "8esGcmYoReadThisReadThisReadThisReadThisReadThisReadThisReadThis"
                + "9esGcmYoReadThisReadThisReadThisReadThisReadThisReadThisReadThis"
                + "10sGcmYoAesGcmEndOfChunkReadThisReadThisReadThisReadThisReadThis";
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
        // XOR the first byte of the tag
        tamperedTag[0] = (byte) (encryptedBytes[inputLength + 1] ^ 1);
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

        // Use a single, large byte array
        final int chunkSize = 3000;
        final byte[] chunk1 = new byte[chunkSize];

        try (final InputStream dataStream = s3Object.getObjectContent()) {
            dataStream.read(chunk1, 0, chunkSize);
        } catch (final IOException ioException) {
            // Just wrap the checked exception so test fails
            throw new RuntimeException(ioException);
        }

        // Trim off the extra 0'd bytes
        final String readOutput = new String(chunk1).trim();
        assertEquals(input, readOutput);
    }

}
