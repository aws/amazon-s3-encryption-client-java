package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.util.HashMap;
import java.util.Map;

public class EncryptionMaterialsRequestTest {

    public PutObjectRequest request = null;
    public EncryptionMaterialsRequest requestBuilder;
    public Map<String, String> encryptionContext = new HashMap<>();

    @BeforeEach
    public void setUp() {
        request = PutObjectRequest.builder().bucket("testBucket").key("testKey").build();
        encryptionContext.put("Key","Value");
        requestBuilder = EncryptionMaterialsRequest.builder()
                .s3Request(request).encryptionContext(encryptionContext).build();
    }

    @Test
    public void testS3Request() {
        Assertions.assertEquals(request, requestBuilder.s3Request());
    }

    @Test
    public void testEncryptionContext() {
        Assertions.assertEquals(encryptionContext, requestBuilder.encryptionContext());
    }
}