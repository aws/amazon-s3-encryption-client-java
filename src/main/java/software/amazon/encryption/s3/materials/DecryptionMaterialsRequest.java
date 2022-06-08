package software.amazon.encryption.s3.materials;

import java.util.List;
import java.util.Map;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

public class DecryptionMaterialsRequest {

    public AlgorithmSuite algorithmSuite;
    public List<EncryptedDataKey> encryptedDataKeys;
    public Map<String, String> encryptionContext;
}
