package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class EncryptedDataKeyTest {

    private EncryptedDataKey actualEncryptedDataKey;
    private byte[] ciphertext;
    private String keyProviderId;
    private byte[] keyProviderInfo;
    
    @BeforeEach
    public void setUp() {
        keyProviderId = "testKeyProviderId";
        keyProviderInfo = new byte[]{20, 10, 30, 5};
        ciphertext = new byte[]{20, 10, 30, 5};

        actualEncryptedDataKey = EncryptedDataKey.builder()
                .keyProviderId(keyProviderId)
                .keyProviderInfo(keyProviderInfo)
                .encryptedDataKey(ciphertext)
                .build();
    }

    @Test
    public void keyProviderId() {
        assertEquals(keyProviderId, actualEncryptedDataKey.keyProviderId());
    }

    @Test
    public void keyProviderInfo() {
        assertEquals(Arrays.toString(keyProviderInfo), Arrays.toString(actualEncryptedDataKey.keyProviderInfo()));
    }

    @Test
    public void ciphertext() {
        assertEquals(Arrays.toString(ciphertext), Arrays.toString(actualEncryptedDataKey.encryptedDatakey()));
    }
}