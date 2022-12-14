package software.amazon.encryption.s3;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;
import software.amazon.encryption.s3.utils.BoundedZerosInputStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.encryption.s3.S3EncryptionClient.isLastPart;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;

public class S3EncryptionClientMultipartUploadTest {
    private static SecretKey AES_KEY;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();
    }

    @Test
    public void multipartPutObject() {
        final String objectKey = "multipart-put-object";

        final int fileSizeLimit = 1024 * 1024 * 110;
        Random rd = new Random();
        byte[] arr = new byte[fileSizeLimit];
        rd.nextBytes(arr);

        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(AES_KEY)
                .enableMultipartPutObject(true)
                .enableDelayedAuthenticationMode(true)
                .build();

        v3Client.putObject(builder -> builder
                .bucket(BUCKET)
                .key(objectKey), RequestBody.fromBytes(arr));

        // Asserts
        ResponseBytes<GetObjectResponse> output = v3Client.getObjectAsBytes(builder -> builder
                .bucket(BUCKET)
                .key(objectKey));

        String outputAsString = Arrays.toString(output.asByteArray());
        assertEquals(Arrays.toString(arr), outputAsString);

        v3Client.deleteObject(builder -> builder.bucket(BUCKET).key(objectKey));
        v3Client.close();
    }
}
