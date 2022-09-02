package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DefaultDataKeyGeneratorTest {

    private final DataKeyGenerator dataKeyGenerator = new DefaultDataKeyGenerator();

    @Test
    public void testGenerateDataKey() {
        SecretKey actualSecretKey = dataKeyGenerator.generateDataKey(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF);
        assertEquals("AES", actualSecretKey.getAlgorithm());
        actualSecretKey = dataKeyGenerator.generateDataKey(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF);
        assertEquals("AES", actualSecretKey.getAlgorithm());
    }
}