package software.amazon.encryption.s3;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsResponse;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalConfiguration;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.TESTVECTORS_BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.TESTVECTORS_KMS_KEY;

public class S3EncryptionClientTestVectorsTest {
    //= specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
    //= type=test
    //# The S3EC SHOULD support decoding the S3 Server's "double encoding".
    @Test
    public void decryptUnicodeTestVectors() {
        S3Client s3EncryptionClient = S3EncryptionClient.builderV4()
                .kmsKeyId(TESTVECTORS_KMS_KEY)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .region(Region.of("us-west-2"))
                .build();
        // Reuse s3EncryptionClient, even though this operation doesn't require encryption
        ListObjectsResponse listObjectsResponse = s3EncryptionClient.listObjects(builder -> builder
                .bucket(TESTVECTORS_BUCKET)
                .build());
        if (!listObjectsResponse.hasContents()) {
            fail("Expected >0 test cases.");
        }
        for (S3Object ciphertext : listObjectsResponse.contents()) {
            String[] vectorInfo = ciphertext.key().split("/");
            if (vectorInfo.length != 4) {
                fail("Invalid test case name: " + ciphertext.key());
            }
            String runtime = vectorInfo[0];
            // String majorVersion = vectorInfo[1];
            String version = vectorInfo[2];
            String vectorName = vectorInfo[3];
            if (!vectorName.contains("unicode-encryption-context")) {
                fail("Only unicode EC tests are currently supported.");
            }
            String expected = "This is a test.\n";
            String metadataValue = vectorName.split("-")[3];
            Map<String, String> encryptionContext = new HashMap<>();
            encryptionContext.put("ec-key", metadataValue);
            ResponseBytes<GetObjectResponse> getObjectResponse = s3EncryptionClient.getObjectAsBytes(builder -> builder
                    .bucket(TESTVECTORS_BUCKET)
                    .key(ciphertext.key())
                    .overrideConfiguration(withAdditionalConfiguration(encryptionContext))
                    .build());
            String output = getObjectResponse.asUtf8String();
            assertEquals(expected, output);
            System.out.printf("Test of v%s for %s passed! Key: %s%n", version, runtime, ciphertext.key());
        }
        s3EncryptionClient.close();
    }
}
