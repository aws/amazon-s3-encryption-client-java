package software.amazon.encryption.s3.examples;

import org.junitpioneer.jupiter.RetryingTest;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import static org.junit.jupiter.api.Assertions.fail;

public class InstructionFileExampleTest {

    @RetryingTest(3)
    public void testInstructionFileExample() {
        final String bucket = S3EncryptionClientTestResources.BUCKET;
        final String kmsKeyId = S3EncryptionClientTestResources.KMS_KEY_ID;
        try {
            InstructionFileExample.simpleKmsKeyringUseInstructionFile(bucket, kmsKeyId);
        } catch (Throwable exception) {
            exception.printStackTrace();
            fail("Instruction File Example Test Failed!!", exception);
        }
    }
}
