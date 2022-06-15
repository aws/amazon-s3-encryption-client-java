package software.amazon.encryption.s3.materials;

import javax.crypto.SecretKey;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

@FunctionalInterface
public interface DataKeyGenerator {
    SecretKey generateDataKey(AlgorithmSuite algorithmSuite);
}
