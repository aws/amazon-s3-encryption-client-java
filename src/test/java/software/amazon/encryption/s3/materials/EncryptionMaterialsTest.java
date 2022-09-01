package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class EncryptionMaterialsTest {

    public List<EncryptedDataKey> encryptedDataKeys = new ArrayList();
    public byte[] plaintextDataKey = null;
    public PutObjectRequest s3Request;
    public EncryptionMaterials actualEncryptionMaterials;
    public Map<String, String> encryptionContext = new HashMap<>();

    @BeforeEach
    public void setUp() {
        s3Request = PutObjectRequest.builder().bucket("testBucket").key("testKey").build();

        encryptionContext.put("Key","Value");
        encryptedDataKeys.add(EncryptedDataKey.builder().keyProviderId("testKeyProviderId").build());;
        actualEncryptionMaterials = EncryptionMaterials.builder()
                .s3Request(s3Request)
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .encryptionContext(encryptionContext)
                .encryptedDataKeys(encryptedDataKeys)
                .plaintextDataKey(plaintextDataKey)
                .build();
    }
    @Test
    void testS3Request() {
        Assertions.assertEquals(s3Request, actualEncryptionMaterials.s3Request());
    }

    @Test
    void testAlgorithmSuite() {
        Assertions.assertEquals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, actualEncryptionMaterials.algorithmSuite());
        Assertions.assertNotEquals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF, actualEncryptionMaterials.algorithmSuite());
    }

    @Test
    void testEncryptionContext() {
        Assertions.assertEquals( encryptionContext, actualEncryptionMaterials.encryptionContext());
    }

    @Test
    void testEncryptedDataKeys() {
        Assertions.assertEquals(encryptedDataKeys, actualEncryptionMaterials.encryptedDataKeys());
    }

    @Test
    void testPlaintextDataKey() {
        Assertions.assertEquals(plaintextDataKey, actualEncryptionMaterials.plaintextDataKey());
    }

    @Test
    void testToBuilder() {
        EncryptionMaterials actualToBuilder = actualEncryptionMaterials.toBuilder().build();
        Assertions.assertEquals(s3Request, actualToBuilder.s3Request());
        Assertions.assertEquals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, actualToBuilder.algorithmSuite());
        Assertions.assertEquals( encryptionContext, actualToBuilder.encryptionContext());
        Assertions.assertEquals(encryptedDataKeys, actualToBuilder.encryptedDataKeys());
        Assertions.assertEquals(plaintextDataKey, actualToBuilder.plaintextDataKey());
    }
}