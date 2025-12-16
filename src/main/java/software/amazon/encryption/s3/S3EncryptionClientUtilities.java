// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Utility class containing shared constants and helper methods for the S3 Encryption Client
 * and S3 Async Encryption Client.
 */
public class S3EncryptionClientUtilities {

    /**
     * The default suffix appended to object keys when creating instruction files.
     * Instruction files store encryption metadata separately from the encrypted object.
     */
    public static final String DEFAULT_INSTRUCTION_FILE_SUFFIX = ".instruction";
    
    /**
     * The minimum allowed buffer size in bytes for safe authentication mode.
     * This is based on the cipher block size of the AES-256-GCM algorithm.
     */
    public static final long MIN_ALLOWED_BUFFER_SIZE_BYTES = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherBlockSizeBytes();
    
    /**
     * The maximum allowed buffer size in bytes for safe authentication mode.
     * This is based on the maximum content length supported by the AES-256-GCM algorithm.
     */
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
                .map(o -> o.toBuilder().key(o.key() + DEFAULT_INSTRUCTION_FILE_SUFFIX).build())
                .collect(Collectors.toList());
    }
}
