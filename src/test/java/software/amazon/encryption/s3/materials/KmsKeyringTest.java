package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.S3EncryptionClientException;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class KmsKeyringTest {

    //@Test
    public void buildAesKeyringWithNullSecureRandomFails() {
        assertThrows(S3EncryptionClientException.class, () -> AesKeyring.builder().secureRandom(null));
    }

    //@Test
    public void buildAesKeyringWithNullDataKeyGeneratorFails() {
        assertThrows(S3EncryptionClientException.class, () -> AesKeyring.builder().dataKeyGenerator(null));
    }

}
