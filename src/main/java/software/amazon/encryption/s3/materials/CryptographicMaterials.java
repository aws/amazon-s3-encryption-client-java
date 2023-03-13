package software.amazon.encryption.s3.materials;

import software.amazon.awssdk.services.s3.model.S3Request;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.util.Map;

public interface CryptographicMaterials {
    AlgorithmSuite algorithmSuite();

    S3Request s3Request();

    Map<String, String> encryptionContext();

    SecretKey dataKey();

    Provider cryptoProvider();
}
