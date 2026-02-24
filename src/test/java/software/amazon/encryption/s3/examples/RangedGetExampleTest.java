package software.amazon.encryption.s3.examples;

import org.junitpioneer.jupiter.RetryingTest;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import static org.junit.jupiter.api.Assertions.fail;

public class RangedGetExampleTest {

    @RetryingTest(3)
    public void testRangedGetExamples() {
        final String bucket = S3EncryptionClientTestResources.BUCKET;
        try {
            RangedGetExample.main(new String[]{bucket});
        } catch (Throwable exception) {
            exception.printStackTrace();
            fail("Ranged Get Test Failed!!", exception);
        }
    }
}
