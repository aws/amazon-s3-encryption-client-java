package software.amazon.encryption.s3.materials;

import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

public class DefaultDataKeyGenerator implements DataKeyGenerator {

    public SecretKey generateDataKey(AlgorithmSuite algorithmSuite) {
        KeyGenerator generator;
        try {
            generator = KeyGenerator.getInstance(algorithmSuite.dataKeyAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Unable to generate a(n) " + algorithmSuite.dataKeyAlgorithm() + " data key", e);
        }

        generator.init(algorithmSuite.dataKeyLengthBits());
        return generator.generateKey();
    }
}
