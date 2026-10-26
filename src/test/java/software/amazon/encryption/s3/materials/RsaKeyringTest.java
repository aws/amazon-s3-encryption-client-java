// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.RetryingTest;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.ContentMetadata;
import software.amazon.encryption.s3.internal.ContentMetadataDecodingStrategy;
import software.amazon.encryption.s3.internal.InstructionFileConfig;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

public class RsaKeyringTest {

    private static KeyPair RSA_KEY_PAIR;

    @BeforeAll
    public static void setUp() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        RSA_KEY_PAIR = keyPairGen.generateKeyPair();
    }

    @RetryingTest(3)
    public void buildAesKeyringWithNullSecureRandomFails() {
        assertThrows(S3EncryptionClientException.class, () -> AesKeyring.builder().secureRandom(null));
    }

    @RetryingTest(3)
    public void buildAesKeyringWithNullDataKeyGeneratorFails() {
        assertThrows(S3EncryptionClientException.class, () -> AesKeyring.builder().dataKeyGenerator(null));
    }

    // RSA-OAEP-SHA1 wraps the data key together with the content cipher ("AES/GCM/NoPadding"). When the
    // decryption materials select the CBC suite (as they would if the content-algorithm metadata read CBC),
    // the wrapped cipher and the selected suite disagree, so the EDK must be rejected.
    @Test
    public void rsaOaepDecryptFailsWhenWrappedCekAlgDoesNotMatchSelectedSuite() {
        RsaKeyring keyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR.getPublic())
                        .privateKey(RSA_KEY_PAIR.getPrivate())
                        .build())
                .build();

        EncryptionMaterials encryptionMaterials = keyring.onEncrypt(EncryptionMaterials.builder()
                .s3Request(PutObjectRequest.builder().bucket("bucket").key("key").build())
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .plaintextDataKey(new byte[32])
                .build());

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.builder()
                .s3Request(GetObjectRequest.builder().bucket("bucket").key("key").build())
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF)
                .build();

        assertThrows(S3EncryptionClientException.class,
                () -> keyring.onDecrypt(decryptionMaterials, encryptionMaterials.encryptedDataKeys()));
    }

    // Removing x-amz-cek-alg and renaming x-amz-key-v2 to x-amz-key makes the object decode as V1, which
    // defaults to the CBC suite while keeping the non-legacy RSA-OAEP-SHA1 wrap-alg. The wrapped cipher is
    // still GCM, so the EDK must be rejected for the CBC suite.
    @Test
    public void rsaOaepDecryptFailsWhenCekAlgHeaderDeletedAndObjectRelabeledV1() {
        RsaKeyring keyring = RsaKeyring.builder()
                .wrappingKeyPair(PartialRsaKeyPair.builder()
                        .publicKey(RSA_KEY_PAIR.getPublic())
                        .privateKey(RSA_KEY_PAIR.getPrivate())
                        .build())
                .build();

        EncryptionMaterials encryptionMaterials = keyring.onEncrypt(EncryptionMaterials.builder()
                .s3Request(PutObjectRequest.builder().bucket("bucket").key("key").build())
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .plaintextDataKey(new byte[32])
                .build());

        Map<String, String> v1Metadata = new HashMap<>();
        v1Metadata.put("x-amz-key", Base64.getEncoder()
                .encodeToString(encryptionMaterials.encryptedDataKeys().get(0).encryptedDatakey()));
        v1Metadata.put("x-amz-wrap-alg", "RSA-OAEP-SHA1");
        v1Metadata.put("x-amz-iv", Base64.getEncoder().encodeToString(new byte[16]));
        v1Metadata.put("x-amz-matdesc", "{}");
        v1Metadata.put("x-amz-tag-len", "128");

        GetObjectRequest getObjectRequest = GetObjectRequest.builder().bucket("bucket").key("key").build();
        ContentMetadata contentMetadata = new ContentMetadataDecodingStrategy(
                InstructionFileConfig.builder().instructionFileClient(mock(S3Client.class)).build())
                .decode(getObjectRequest, GetObjectResponse.builder().metadata(v1Metadata).build());
        assertEquals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF, contentMetadata.algorithmSuite());

        DecryptionMaterials decryptionMaterials = DecryptionMaterials.builder()
                .s3Request(getObjectRequest)
                .algorithmSuite(contentMetadata.algorithmSuite())
                .encryptionContext(contentMetadata.encryptionContext())
                .materialsDescription(contentMetadata.materialsDescription())
                .build();

        assertThrows(S3EncryptionClientException.class,
                () -> keyring.onDecrypt(decryptionMaterials,
                        Collections.singletonList(contentMetadata.encryptedDataKey())));
    }
}
