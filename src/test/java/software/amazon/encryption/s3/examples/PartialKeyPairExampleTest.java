package software.amazon.encryption.s3.examples;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

public class PartialKeyPairExampleTest {

    @Test
    public void invokeTestPKPExamples() {
        for (int i = 0; i <= 100; i++) {
            if (i % 5 == 0) {
                System.out.println(i + "/100");
            }
            testPartialKeyPairExamples();
        }
    }

    //@Test
    public void testPartialKeyPairExamples() {
        final String bucket = S3EncryptionClientTestResources.BUCKET;

        PartialKeyPairExample.main(new String[]{bucket});
    }
}
