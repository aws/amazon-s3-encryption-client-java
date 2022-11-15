package software.amazon.encryption.s3.materials;

import java.security.Provider;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.CryptoFactory;

public class DefaultDataKeyGenerator implements DataKeyGenerator {

    public SecretKey generateDataKey(AlgorithmSuite algorithmSuite, Provider provider) {
        KeyGenerator generator = CryptoFactory.generateKey(algorithmSuite.dataKeyAlgorithm(), provider);
        generator.init(algorithmSuite.dataKeyLengthBits());
        return generator.generateKey();
    }
}
