package software.amazon.encryption.s3.materials;

import javax.crypto.SecretKey;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

public interface DataKeyGenerator {
    SecretKey generateDataKey(AlgorithmSuite algorithmSuite);
}
