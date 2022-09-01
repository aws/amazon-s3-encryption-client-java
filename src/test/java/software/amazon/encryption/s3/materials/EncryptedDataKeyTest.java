package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

public class EncryptedDataKeyTest {

    public EncryptedDataKey encryptedDataKey;
    public byte[] ciphertext;
    public String keyProviderId;
    public byte[] keyProviderInfo;
    @BeforeEach
    public void setUp() {
        keyProviderId = "testKeyProviderId";
        keyProviderInfo = new byte[]{20, 10, 30, 5};
        ciphertext = new byte[]{20, 10, 30, 5};

        encryptedDataKey = EncryptedDataKey.builder()
                .keyProviderId(keyProviderId)
                .keyProviderInfo(keyProviderInfo)
                .ciphertext(ciphertext)
                .build();
    }

    @Test
    public void keyProviderId() {
        Assertions.assertEquals(keyProviderId, encryptedDataKey.keyProviderId());
    }

    @Test
    public void keyProviderInfo() {
        Assertions.assertEquals(Arrays.toString(keyProviderInfo), Arrays.toString(encryptedDataKey.keyProviderInfo()));
    }

    @Test
    public void ciphertext() {
        Assertions.assertEquals(Arrays.toString(ciphertext), Arrays.toString(encryptedDataKey.ciphertext()));
    }
}