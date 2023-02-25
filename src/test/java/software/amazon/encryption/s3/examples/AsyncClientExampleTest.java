package software.amazon.encryption.s3.examples;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

public class AsyncClientExampleTest {

    @Test
    public void testAsyncClientExamples() {
        final String bucket = S3EncryptionClientTestResources.BUCKET;
        // Installs ACCP as default provider
        com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider.install();

        AsyncClientExample.main(new String[]{bucket});
    }
}
