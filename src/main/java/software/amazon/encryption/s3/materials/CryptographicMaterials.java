package software.amazon.encryption.s3.materials;

import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

public interface CryptographicMaterials {
    public AlgorithmSuite algorithmSuite();
}
