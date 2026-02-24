package software.amazon.encryption.s3.examples;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import static org.junit.jupiter.api.Assertions.fail;

public class ReEncryptInstructionFileExampleTest {

    @RetryingTest(3)
    public void testSimpleAesKeyringReEncryptInstructionFile() {
        final String bucket = S3EncryptionClientTestResources.BUCKET;
        try {
            ReEncryptInstructionFileExample.simpleAesKeyringReEncryptInstructionFile(bucket);
        } catch (Throwable exception) {
            exception.printStackTrace();
            fail("AES Keyring ReEncrypt Instruction File Test Failed!!", exception);
        }
    }

    @RetryingTest(3)
    public void testSimpleRsaKeyringReEncryptInstructionFile() {
        final String bucket = S3EncryptionClientTestResources.BUCKET;
        try {
            ReEncryptInstructionFileExample.simpleRsaKeyringReEncryptInstructionFile(bucket);
        } catch (Throwable exception) {
            exception.printStackTrace();
            fail("RSA Keyring ReEncrypt Instruction File Test Failed!!", exception);
        }
    }

    @RetryingTest(3)
    public void testSimpleRsaKeyringReEncryptInstructionFileWithCustomSuffix() {
        final String bucket = S3EncryptionClientTestResources.BUCKET;
        try {
            ReEncryptInstructionFileExample.simpleRsaKeyringReEncryptInstructionFileWithCustomSuffix(bucket);
        } catch (Throwable exception) {
            exception.printStackTrace();
            fail("RSA Keyring ReEncrypt Instruction File With Custom Suffix Test Failed!!", exception);
        }
    }
}
