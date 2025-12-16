// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import software.amazon.encryption.s3.S3EncryptionClientException;

public class MetadataKeyConstantsTest {

    @Test
    public void testWrappingAlgorithmCompression() {
        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval, and vice versa on write.
        String result = MetadataKeyConstants.compressWrappingAlgorithm("AES/GCM");
        assertEquals("02", result);

        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval, and vice versa on write.
        result = MetadataKeyConstants.compressWrappingAlgorithm("kms+context");
        assertEquals("12", result);

        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval, and vice versa on write.
        result = MetadataKeyConstants.compressWrappingAlgorithm("RSA-OAEP-SHA1");
        assertEquals("22", result);

        // Test unknown algorithm throws exception
        assertThrows(S3EncryptionClientException.class, () -> {
            MetadataKeyConstants.compressWrappingAlgorithm("not-a-known-algorithm");
        });
    }

    @Test
    public void testWrappingAlgorithmDecompression() {
        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval
        String result = MetadataKeyConstants.decompressWrappingAlgorithm("02");
        assertEquals("AES/GCM", result);

        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval
        result = MetadataKeyConstants.decompressWrappingAlgorithm("12");
        assertEquals("kms+context", result);

        //= specification/s3-encryption/data-format/content-metadata.md#v3-only
        //= type=test
        //# - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval
        result = MetadataKeyConstants.decompressWrappingAlgorithm("22");
        assertEquals("RSA-OAEP-SHA1", result);

        // Test unknown compressed value throws exception
        assertThrows(S3EncryptionClientException.class, () -> {
            MetadataKeyConstants.decompressWrappingAlgorithm("99");
        });
    }
}
