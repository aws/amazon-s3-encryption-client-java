// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

/**
 * Content-encryption algorithm handling shared by the Kms+Context decrypt paths of
 * {@link KmsKeyring} and {@link KmsDiscoveryKeyring}.
 */
final class KmsContentAlgorithm {

    private static final String ENCRYPTION_CONTEXT_ALGORITHM_KEY = "aws:x-amz-cek-alg";

    private KmsContentAlgorithm() {
    }

    /**
     * The stored content-encryption algorithm (KMS-authenticated) MUST match the algorithm suite
     * selected from content metadata (unauthenticated).
     */
    static void validate(DecryptionMaterials materials) {
        String storedContentAlgorithm = materials.encryptionContext().get(ENCRYPTION_CONTEXT_ALGORITHM_KEY);
        if (storedContentAlgorithm != null
                && !storedContentAlgorithm.equals(forSuite(materials.algorithmSuite()))) {
            throw new S3EncryptionClientException(String.format(
                    "The content encryption algorithm in the KMS-authenticated encryption context (%s) does not "
                            + "match the algorithm suite selected for decryption (%s).",
                    storedContentAlgorithm, materials.algorithmSuite().name()));
        }
    }

    /**
     * Return content-encryption algorithm for a given AlgorithmSuite. A CTR suite returns the value of its
     * GCM counterpart, because ranged gets decrypt a GCM object with the CTR suite.
     */
    static String forSuite(AlgorithmSuite algorithmSuite) {
        switch (algorithmSuite) {
            case ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY:
            case ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY:
                return AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.idAsString();
            case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
            case ALG_AES_256_CTR_IV16_TAG16_NO_KDF:
                return AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherName();
            default:
                return algorithmSuite.cipherName();
        }
    }
}
