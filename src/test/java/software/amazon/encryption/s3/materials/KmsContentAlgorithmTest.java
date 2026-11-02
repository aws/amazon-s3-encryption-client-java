// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.util.Collections;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class KmsContentAlgorithmTest {

    private static Stream<Arguments> contentAlgorithmBySuite() {
        return Stream.of(
                Arguments.of(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, "115"),
                Arguments.of(AlgorithmSuite.ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY, "115"),
                Arguments.of(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF, "AES/GCM/NoPadding"),
                Arguments.of(AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF, "AES/GCM/NoPadding"),
                Arguments.of(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF, "AES/CBC/PKCS5Padding"));
    }

    @ParameterizedTest
    @MethodSource("contentAlgorithmBySuite")
    public void forSuiteReturnsStoredContentAlgorithm(AlgorithmSuite suite, String expected) {
        assertEquals(expected, KmsContentAlgorithm.forSuite(suite));
    }

    @ParameterizedTest
    @MethodSource("contentAlgorithmBySuite")
    public void validateAcceptsMatchingContentAlgorithm(AlgorithmSuite suite, String storedContentAlgorithm) {
        DecryptionMaterials materials = materials(suite,
                Collections.singletonMap("aws:x-amz-cek-alg", storedContentAlgorithm));
        assertDoesNotThrow(() -> KmsContentAlgorithm.validate(materials));
    }

    @ParameterizedTest
    @EnumSource(AlgorithmSuite.class)
    public void validateSkipsWhenContentAlgorithmIsAbsent(AlgorithmSuite suite) {
        DecryptionMaterials materials = materials(suite,
                Collections.singletonMap("kms_cmk_id", "arn:aws:kms:us-west-2:111122223333:key/example"));
        assertDoesNotThrow(() -> KmsContentAlgorithm.validate(materials));
    }

    @Test
    public void forSuiteCoversEveryAlgorithmSuite() {
        assertEquals(AlgorithmSuite.values().length, contentAlgorithmBySuite().count());
    }

    private static DecryptionMaterials materials(AlgorithmSuite suite, Map<String, String> encryptionContext) {
        return DecryptionMaterials.builder()
                .s3Request(GetObjectRequest.builder().bucket("bucket").key("key").build())
                .algorithmSuite(suite)
                .encryptionContext(encryptionContext)
                .build();
    }
}
