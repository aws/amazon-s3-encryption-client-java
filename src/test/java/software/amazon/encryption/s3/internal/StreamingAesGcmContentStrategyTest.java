// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

public class StreamingAesGcmContentStrategyTest {

    private static SecretKey AES_KEY;

    @BeforeAll
    public static void setUp() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();
    }

    @Test
    public void buildStreamingAesGcmContentStrategyWithNullSecureRandomFails() {
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class, () -> StreamingAesGcmContentStrategy.builder().secureRandom(null));
        assertTrue(exception.getMessage().contains("SecureRandom provided to StreamingAesGcmContentStrategy cannot be null"));
    }

    @Test
    public void testEncryptContentValidatesMaxContentLength() {
        StreamingAesGcmContentStrategy strategy = StreamingAesGcmContentStrategy.builder().build();
        
        // Create materials with plaintext length exceeding max for GCM
        long exceededLength = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherMaxContentLengthBytes() + 1;
        EncryptionMaterials materials = EncryptionMaterials.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .plaintextDataKey(AES_KEY.getEncoded())
                .plaintextLength(exceededLength)
                .build();
        
        AsyncRequestBody content = AsyncRequestBody.fromString("test");

        //= specification/s3-encryption/encryption.md#content-encryption
        //= type=test
        //# The client MUST validate that the length of the plaintext bytes does not exceed the algorithm suite's cipher's maximum content length in bytes.
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class,
                () -> strategy.encryptContent(materials, content));
        assertTrue(exception.getMessage().contains("maximum length allowed for GCM encryption"));
    }

    @Test
    public void testInitMultipartEncryptionValidatesMaxContentLength() {
        StreamingAesGcmContentStrategy strategy = StreamingAesGcmContentStrategy.builder().build();
        
        // Create materials with plaintext length exceeding max for GCM
        long exceededLength = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherMaxContentLengthBytes() + 1;
        EncryptionMaterials materials = EncryptionMaterials.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .plaintextDataKey(AES_KEY.getEncoded())
                .plaintextLength(exceededLength)
                .build();

        //= specification/s3-encryption/encryption.md#content-encryption
        //= type=test
        //# The client MUST validate that the length of the plaintext bytes does not exceed the algorithm suite's cipher's maximum content length in bytes.
        S3EncryptionClientException exception = assertThrows(S3EncryptionClientException.class,
                () -> strategy.initMultipartEncryption(materials));
        assertTrue(exception.getMessage().contains("maximum length allowed for GCM encryption"));
    }

    //= specification/s3-encryption/encryption.md#content-encryption
    //= type=test
    //# The generated IV or Message ID MUST be set or returned from the encryption process such that it can be included in the content metadata.
    @Test
    public void testEncryptContentWithNonCommitingAlgorithm() {
        StreamingAesGcmContentStrategy strategy = StreamingAesGcmContentStrategy.builder().build();
        
        EncryptionMaterials materials = EncryptionMaterials.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .plaintextDataKey(AES_KEY.getEncoded())
                .plaintextLength(100L)
                .build();
        
        AsyncRequestBody content = AsyncRequestBody.fromString("test");
        EncryptedContent encryptContent = strategy.encryptContent(materials, content);
        //= specification/s3-encryption/encryption.md#content-encryption
        //= type=test
        //# The generated IV or Message ID MUST be set or returned from the encryption process such that it can be included in the content metadata.
        assertNotNull(encryptContent.iv());
        assertNull(encryptContent.messageId());
        //= specification/s3-encryption/encryption.md#content-encryption
        //= type=test
        //# The client MUST generate an IV or Message ID using the length of the IV or Message ID defined in the algorithm suite.
        assertEquals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.iVLengthBytes(), encryptContent.iv().length);
    }
}
