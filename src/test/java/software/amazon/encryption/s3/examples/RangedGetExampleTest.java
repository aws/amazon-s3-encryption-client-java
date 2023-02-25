package software.amazon.encryption.s3.examples;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

public class RangedGetExampleTest {

    @Test
    public void testRangedGetExamples() {
        final String bucket = S3EncryptionClientTestResources.BUCKET;
        RangedGetExample.main(new String[]{bucket});
    }
}
