package software.amazon.encryption.s3.examples;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import static org.junit.jupiter.api.Assertions.fail;

public class MultipartUploadExampleTest {

    @Test
    public void testMultipartUploadExamples() {
        int success = 0, failures = 0;
        for(int i=0; i < 100; i++) {
            final String bucket = S3EncryptionClientTestResources.BUCKET;
            try {
                MultipartUploadExample.main(new String[]{bucket});
                success++;
            } catch (Throwable exception) {
                exception.printStackTrace();
                fail("Multipart Example Test Failed!!", exception);
                failures++;
            }
        }
        System.out.println("testMultipartUploadExamples: Success: "+success+" Failures: "+failures);
    }
}
