package software.amazon.encryption.s3.examples;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import java.io.IOException;

public class MultipartUploadExampleTest {

    @Test
    public void testMultipartUploadExamples() throws IOException {
        final String bucket = S3EncryptionClientTestResources.BUCKET;
        MultipartUploadExample.main(new String[]{bucket});
    }
}
