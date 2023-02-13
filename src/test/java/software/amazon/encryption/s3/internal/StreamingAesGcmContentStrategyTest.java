package software.amazon.encryption.s3.internal;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import software.amazon.encryption.s3.S3EncryptionClientException;

public class StreamingAesGcmContentStrategyTest {

    //@Test
    public void buildStreamingAesGcmContentStrategyWithNullSecureRandomFails() {
      assertThrows(S3EncryptionClientException.class, () -> StreamingAesGcmContentStrategy.builder().secureRandom(null));
    }

}
