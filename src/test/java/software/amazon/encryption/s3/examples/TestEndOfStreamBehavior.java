package software.amazon.encryption.s3.examples;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.*;

public class TestEndOfStreamBehavior {
    private static final Region DEFAULT_REGION = KMS_REGION;
    private static final String KEY = "GHI-300.txt";
    @SuppressWarnings("SpellCheckingInspection")
    private static final byte[] CONTENT = new String(new char[4])
        .replace("\0", "abcdefghijklmnopqrstuvwxyz0123456789")
        .getBytes();
    /** The encryption key to use in client-side encryption tests. */
    protected static final KeyPair KEY_PAIR;

    static {
        try {
            KEY_PAIR = S3EncryptionClientTestResources.getRSAKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static Stream<S3Client> clientProvider() {
        return Stream.of(
            getClient(DEFAULT_REGION),
            getEncryptionClient(KEY_PAIR, DEFAULT_REGION));
    }

    @ParameterizedTest
    @MethodSource("clientProvider")
    void testEndOfStreamBehavior(final S3Client client) throws Exception {
        // Delete the data if it exists
        final DeleteObjectRequest deleteRequest = DeleteObjectRequest.builder()
            .bucket(BUCKET)
            .key(KEY)
            .build();

        client.deleteObject(deleteRequest);

        // Upload the data
        final PutObjectRequest uploadRequest =
            PutObjectRequest.builder().bucket(BUCKET).key(KEY).build();
        client.putObject(uploadRequest, RequestBody.fromBytes(CONTENT));
        // wait 5 seconds for the data to be uploaded
        Thread.sleep(5000);

        // Actual test
        final GetObjectRequest downloadRequest =
            GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(KEY)
                .range("bytes=0-15")
                .build();

        final InputStream stream = client.getObject(downloadRequest);

        // Buffer capacity matters !!!
        // Behavior difference when the capacity is same as the content length (i.e. 16) of the ranged query
        final ByteBuffer buffer = ByteBuffer.allocate(16);
        final byte[] underlyingBuffer = buffer.array();
        final int capacity = buffer.capacity();

        final int END_OF_STREAM = -1;
        int byteRead = 0;
        int startPosition = 0;
        while (byteRead != END_OF_STREAM) {
            int lenToRead = capacity - startPosition;
            System.out.println("Start position: " + startPosition + " Length to read: " + lenToRead);
            byteRead = stream.read(underlyingBuffer, startPosition, lenToRead);
            System.out.println("Read " + byteRead + " bytes");
            startPosition += byteRead;
            if (byteRead == 0) {
                // Now we always get this error; we probably were always getting this error, but the log was not writing.
                throw new AssertionError(
                    String.format("Looping indefinitely with an encryption client, as startPosition is not increasing." +
                            "\n lenToRead: %s \t byteRead: %s \t startPosition: %s",
                        lenToRead, byteRead, startPosition));
            }
        }
    }

    public static S3Client getEncryptionClient(final KeyPair keyPair, final Region region) {
        return S3EncryptionClient.builder()
            .rsaKeyPair(keyPair)
            .enableLegacyUnauthenticatedModes(true)
            .wrappedClient(getClient(region))
            .wrappedAsyncClient(getAsyncClient(region))
            .build();
    }

    public static S3Client getClient(final Region region) {
        return S3Client.builder()
            .region(region)
            .credentialsProvider(CREDENTIALS)
            .httpClient(HTTP_CLIENT)
            .build();
    }

    public static S3AsyncClient getAsyncClient(final Region region) {
        final SdkAsyncHttpClient nettyHttpClient =
            NettyNioAsyncHttpClient.builder().maxConcurrency(100).build();
        return S3AsyncClient.builder()
            .region(region)
            .credentialsProvider(CREDENTIALS)
            .httpClient(nettyHttpClient)
            .build();
    }
}
