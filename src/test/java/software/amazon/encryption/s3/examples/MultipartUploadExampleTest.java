package software.amazon.encryption.s3.examples;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import java.io.IOException;

public class MultipartUploadExampleTest {

    @Test
    public void testLowLevelMultipartUploadExamples() throws IOException {
        final String bucket = S3EncryptionClientTestResources.BUCKET;
        // Installs ACCP as default provider
        com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider.install();

        MultipartUploadExample.main(new String[]{bucket});
    }
}
