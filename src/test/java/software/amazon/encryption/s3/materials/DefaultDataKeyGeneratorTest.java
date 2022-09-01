package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import javax.crypto.SecretKey;

public class DefaultDataKeyGeneratorTest {

    private DataKeyGenerator dataKeyGenerator;

    @BeforeEach
    public void setUp() {
        dataKeyGenerator = new DefaultDataKeyGenerator();
    }

    @Test
    public void testGenerateDataKey() {
        SecretKey actualSecretKey = dataKeyGenerator.generateDataKey(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF);
        Assertions.assertEquals("AES", actualSecretKey.getAlgorithm());
        actualSecretKey = dataKeyGenerator.generateDataKey(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF);
        Assertions.assertEquals("AES", actualSecretKey.getAlgorithm());
    }
}