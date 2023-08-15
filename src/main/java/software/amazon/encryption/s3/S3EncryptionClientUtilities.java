// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.util.List;
import java.util.stream.Collectors;

/**
 * This class contains that which can be shared between the default S3 Encryption
 * Client and its Async counterpart.
 */
public class S3EncryptionClientUtilities {

    public static final String INSTRUCTION_FILE_SUFFIX = ".instruction";
    public static final long MIN_ALLOWED_BUFFER_SIZE_BYTES = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherBlockSizeBytes();
    public static final long MAX_ALLOWED_BUFFER_SIZE_BYTES = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherMaxContentLengthBytes();

    /**
     * The Default Buffer Size for Safe authentication is set to 64MiB.
     */
    public static final long DEFAULT_BUFFER_SIZE_BYTES = 64 * 1024 * 1024;

    /**
     * For a given DeleteObjectsRequest, return a list of ObjectIdentifiers
     * representing the corresponding instruction files to delete.
     * @param request a DeleteObjectsRequest
     * @return the list of ObjectIdentifiers for instruction files to delete
     */
    static List<ObjectIdentifier> instructionFileKeysToDelete(final DeleteObjectsRequest request) {
        return request.delete().objects().stream()
                .map(o -> o.toBuilder().key(o.key() + INSTRUCTION_FILE_SUFFIX).build())
                .collect(Collectors.toList());
    }
}
