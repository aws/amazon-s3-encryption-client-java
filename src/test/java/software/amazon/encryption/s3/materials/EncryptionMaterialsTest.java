package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class EncryptionMaterialsTest {

    private List<EncryptedDataKey> encryptedDataKeys = new ArrayList();
    private byte[] plaintextDataKey;
    private PutObjectRequest s3Request;
    private EncryptionMaterials actualEncryptionMaterials;
    private Map<String, String> encryptionContext = new HashMap<>();

    @BeforeEach
    public void setUp() {
        s3Request = PutObjectRequest.builder().bucket("testBucket").key("testKey").build();
        encryptionContext.put("Key","Value");
        encryptedDataKeys.add(EncryptedDataKey.builder().keyProviderId("testKeyProviderId").build());
        plaintextDataKey = "Test String".getBytes();
        actualEncryptionMaterials = EncryptionMaterials.builder()
                .s3Request(s3Request)
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .encryptionContext(encryptionContext)
                .encryptedDataKeys(encryptedDataKeys)
                .plaintextDataKey(plaintextDataKey)
                .build();
    }
    @RepeatedTest(10)
    void testS3Request() {
        assertEquals(s3Request, actualEncryptionMaterials.s3Request());
    }

    @RepeatedTest(10)
    void testAlgorithmSuite() {
        assertEquals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, actualEncryptionMaterials.algorithmSuite());
        assertNotEquals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF, actualEncryptionMaterials.algorithmSuite());
    }

    @RepeatedTest(10)
    void testEncryptionContext() {
        assertEquals(encryptionContext, actualEncryptionMaterials.encryptionContext());
    }

    @RepeatedTest(10)
    void testEncryptedDataKeys() {
        assertEquals(encryptedDataKeys, actualEncryptionMaterials.encryptedDataKeys());
    }

    @RepeatedTest(10)
    void testPlaintextDataKey() {
        assertEquals(Arrays.toString(plaintextDataKey), Arrays.toString(actualEncryptionMaterials.plaintextDataKey()));
    }

    @RepeatedTest(10)
    void testToBuilder() {
        EncryptionMaterials actualToBuilder = actualEncryptionMaterials.toBuilder().build();
        assertEquals(s3Request, actualToBuilder.s3Request());
        assertEquals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, actualToBuilder.algorithmSuite());
        assertEquals(encryptionContext, actualToBuilder.encryptionContext());
        assertEquals(encryptedDataKeys, actualToBuilder.encryptedDataKeys());
        assertEquals(Arrays.toString(plaintextDataKey), Arrays.toString(actualToBuilder.plaintextDataKey()));
    }
}