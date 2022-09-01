package software.amazon.encryption.s3.internal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptedDataKey;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class ContentMetadataTest {

    public EncryptedDataKey encryptedDataKey;
    public ContentMetadata actualContentMetadata;
    public String encryptedDataKeyAlgorithm;
    public final Map<String, String> encryptedDataKeyContext = new HashMap<>();
    public byte[] contentNonce;
    @BeforeEach
    public void setUp() {
        encryptedDataKey = EncryptedDataKey.builder()
                .keyProviderId("TestKeyProviderId")
                .keyProviderInfo("Test String".getBytes())
                .ciphertext("Test String".getBytes())
                .build();
        contentNonce = "Test String".getBytes();
        encryptedDataKeyAlgorithm =   "Test Algorithm";
        encryptedDataKeyContext.put("testKey", "testValue");
        actualContentMetadata = ContentMetadata.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .encryptedDataKey(encryptedDataKey)
                .contentNonce(contentNonce)
                .encryptedDataKeyAlgorithm(encryptedDataKeyAlgorithm)
                .encryptedDataKeyContext(encryptedDataKeyContext)
                .build();
    }

    @Test
    public void testAlgorithmSuite() {
        Assertions.assertEquals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, actualContentMetadata.algorithmSuite());
        Assertions.assertNotEquals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF, actualContentMetadata.algorithmSuite());
    }

    @Test
    public void testEncryptedDataKey() {
        Assertions.assertEquals( encryptedDataKey, actualContentMetadata.encryptedDataKey());
    }

    @Test
    public void testEncryptedDataKeyAlgorithm() {
        Assertions.assertEquals(encryptedDataKeyAlgorithm, actualContentMetadata.encryptedDataKeyAlgorithm());
    }

    @Test
    public void testEncryptedDataKeyContext() {
        Assertions.assertEquals(encryptedDataKeyContext, actualContentMetadata.encryptedDataKeyContext());
    }

    @Test
    public void testContentNonce() {
        Assertions.assertEquals(Arrays.toString(contentNonce),Arrays.toString(actualContentMetadata.contentNonce()));
    }
}

