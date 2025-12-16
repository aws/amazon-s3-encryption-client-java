package software.amazon.encryption.s3.materials;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_KEY_ID;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.encryption.s3.CommitmentPolicy;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

public class CryptographicMaterialsManagerTest {

    @Test
    public void testCMMReturningNullEncryptionMaterialsThrowsException() {
        final String objectKey = appendTestSuffix("test-cmm-null-encryption-materials");

        // Create a mock CMM that returns null for encryption materials
        CryptographicMaterialsManager mockCMM = mock(CryptographicMaterialsManager.class);
        when(mockCMM.getEncryptionMaterials(any(EncryptionMaterialsRequest.class)))
                .thenReturn(null);

        // Create S3 Encryption Client with the mocked CMM
        S3Client encryptionClient = S3EncryptionClient.builderV4()
                .cryptoMaterialsManager(mockCMM)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .build();

        // Attempt to put an object - should throw exception when CMM returns null
        S3EncryptionClientException encryptionException = assertThrows(S3EncryptionClientException.class, () -> {
            encryptionClient.putObject(builder -> builder
                    .bucket(BUCKET)
                    .key(objectKey), RequestBody.fromBytes("test-data".getBytes()));
        }, "Expected exception when CMM returns null for encryption materials");

        assertTrue(encryptionException.getMessage().contains("Encryption materials cannot be null"));

        // Cleanup
        encryptionClient.close();
    }

    @Test
    public void testCMMReturningNullDecryptionMaterialsThrowsException() {
        final String objectKey = appendTestSuffix("test-cmm-null-decryption-materials");

        // Create a mock CMM that returns null for decryption materials
        CryptographicMaterialsManager mockCMM = mock(CryptographicMaterialsManager.class);
        when(mockCMM.decryptMaterials(any(DecryptMaterialsRequest.class)))
                .thenReturn(null);

        // Create a valid S3 Encryption Client with KMS for encryption
        S3Client validEncryptionClient = S3EncryptionClient.builderV4()
                .kmsKeyId(KMS_KEY_ID)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .build();

        // Create S3 Encryption Client with the mocked CMM for decryption
        S3Client decryptionClient = S3EncryptionClient.builderV4()
                .cryptoMaterialsManager(mockCMM)
                .encryptionAlgorithm(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .commitmentPolicy(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
                .build();

        // Put an object using the valid client
        validEncryptionClient.putObject(builder -> builder.bucket(BUCKET).key(objectKey),
                RequestBody.fromBytes("test-data".getBytes()));

        // Attempt to get the object using the mocked CMM that returns null
        Exception decryptionException = assertThrows(Exception.class, () -> {
            decryptionClient.getObject(builder -> builder.bucket(BUCKET).key(objectKey));
        }, "Expected exception when CMM returns null for decryption materials");

        assertTrue(decryptionException.getMessage().contains("Decryption materials cannot be null"));

        // Cleanup
        deleteObject(BUCKET, objectKey, validEncryptionClient);
        decryptionClient.close();
        validEncryptionClient.close();
    }
}
