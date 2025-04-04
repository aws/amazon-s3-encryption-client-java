package software.amazon.encryption.s3.examples;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import static org.junit.jupiter.api.Assertions.fail;

public class AsyncClientExampleTest {

    @Test
    public void testAsyncClientExamples() {
        final String bucket = S3EncryptionClientTestResources.BUCKET;
        try {
            AsyncClientExample.main(new String[]{bucket});
        } catch (Throwable exception) {
            exception.printStackTrace();
            fail("Async Example Test Failed!!", exception);
        }
    }
}
