package software.amazon.encryption.s3.examples;

import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.StaticEncryptionMaterialsProvider;
import com.amazonaws.util.IOUtils;
import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PartialKeyPairExampleTest {

    @Test
    public void testPartialKeyPairExamples() {
        final String bucket = S3EncryptionClientTestResources.BUCKET;

        for (int i = 0; i <= 50; i++) {
            if (i % 10 == 0) {
                System.out.println(i + "/1000");
            }
            PartialKeyPairExample.main(new String[]{bucket});
        }

    }

    @Test
    public void simpleRoundTripV2() throws NoSuchAlgorithmException, IOException {
        for (int i = 0; i <= 50; i++) {
            if (i % 10 == 0) {
                System.out.println(i + "/100");
            }
            roundTripV2();
        }

    }

    private void roundTripV2() throws NoSuchAlgorithmException, IOException {
        final String bucket = S3EncryptionClientTestResources.BUCKET;
        final String objectKey = "nameOfObjectForSimpleRoundtripV2";
        final SecretKey AES_KEY;
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();

        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();
        final String input = "This is a sample string to encrypt.";

        v2Client.putObject(bucket, objectKey, input);
        final S3Object result = v2Client.getObject(bucket, objectKey);
        final String resultString = IOUtils.toString(result.getObjectContent());
        assertEquals(input, resultString);

    }
}
