package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.RepeatedTest;
import software.amazon.encryption.s3.S3EncryptionClientException;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class RsaKeyringTest {

    @RepeatedTest(10)
    public void buildAesKeyringWithNullSecureRandomFails() {
        assertThrows(S3EncryptionClientException.class, () -> AesKeyring.builder().secureRandom(null));
    }

    @RepeatedTest(10)
    public void buildAesKeyringWithNullDataKeyGeneratorFails() {
        assertThrows(S3EncryptionClientException.class, () -> AesKeyring.builder().dataKeyGenerator(null));
    }
}
