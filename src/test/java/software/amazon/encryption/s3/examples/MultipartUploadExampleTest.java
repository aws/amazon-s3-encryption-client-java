package software.amazon.encryption.s3.examples;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import static org.junit.jupiter.api.Assertions.fail;

public class MultipartUploadExampleTest {
    private static boolean testCasePassed = false;

    @Test
    public void testMultipartUploadExamples() {
        if(testCasePassed) {
            return;
        }

        final String bucket = S3EncryptionClientTestResources.BUCKET;
        try {
            MultipartUploadExample.main(new String[]{bucket});
            testCasePassed = true;
        } catch (Throwable exception) {
            exception.printStackTrace();
            fail("Multipart Example Test Failed!!", exception);
        }
    }
}
