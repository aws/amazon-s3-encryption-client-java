// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientException;

import java.util.Map;

//= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
//= type=implication
//# The "x-amz-meta-" prefix is automatically added by the S3 server and MUST NOT be included in implementation code.
public class MetadataKeyConstants {

    //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=implication
    //# The "x-amz-" prefix denotes that the metadata is owned by an Amazon product and MUST be prepended to all S3EC metadata mapkeys.
    private static final String AMZ_PREFIX = "x-amz-";

    public static final String ENCRYPTED_DATA_KEY_V1 = AMZ_PREFIX + "key";
    public static final String ENCRYPTED_DATA_KEY_V2 = AMZ_PREFIX + "key-v2";
    // This is the name of the keyring/algorithm e.g. AES/GCM or kms+context
    public static final String ENCRYPTED_DATA_KEY_ALGORITHM = AMZ_PREFIX + "wrap-alg";
    public static final String ENCRYPTED_DATA_KEY_MATDESC_OR_EC = AMZ_PREFIX + "matdesc";

    public static final String CONTENT_IV = AMZ_PREFIX + "iv";
    // This is usually an actual Java cipher e.g. AES/GCM/NoPadding
    public static final String CONTENT_CIPHER = AMZ_PREFIX + "cek-alg";
    public static final String CONTENT_CIPHER_TAG_LENGTH = AMZ_PREFIX + "tag-len";
    // Only used in instruction files to identify them as such
    public static final String INSTRUCTION_FILE = AMZ_PREFIX + "crypto-instr-file";

    // V3 format, which uses compression
    //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=implication
    //# - This mapkey("x-amz-c") SHOULD be represented by a constant named "CONTENT_CIPHER_V3" or similar in the implementation code.
    public static final String CONTENT_CIPHER_V3 = AMZ_PREFIX + "c";
    //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=implication
    //# - This mapkey("x-amz-3") SHOULD be represented by a constant named "ENCRYPTED_DATA_KEY_V3" or similar in the implementation code.
    public static final String ENCRYPTED_DATA_KEY_V3 = AMZ_PREFIX + "3";
    //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=implication
    //# - This mapkey("x-amz-m") SHOULD be represented by a constant named "MAT_DESC_V3" or similar in the implementation code.
    public static final String MAT_DESC_V3 = AMZ_PREFIX + "m";
    //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=implication
    //# - This mapkey("x-amz-t") SHOULD be represented by a constant named "ENCRYPTION_CONTEXT_V3" or similar in the implementation code.
    public static final String ENCRYPTION_CONTEXT_V3 = AMZ_PREFIX + "t";
    //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=implication
    //# - This mapkey("x-amz-w") SHOULD be represented by a constant named "ENCRYPTED_DATA_KEY_ALGORITHM_V3" or similar in the implementation code.
    public static final String ENCRYPTED_DATA_KEY_ALGORITHM_V3 = AMZ_PREFIX + "w";
    //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=implication
    //# - This mapkey("x-amz-d") SHOULD be represented by a constant named "KEY_COMMITMENT_V3" or similar in the implementation code.
    public static final String KEY_COMMITMENT_V3 = AMZ_PREFIX + "d";
    //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
    //= type=implication
    //# - This mapkey("x-amz-i") SHOULD be represented by a constant named "MESSAGE_ID_V3" or similar in the implementation code.
    public static final String MESSAGE_ID_V3 = AMZ_PREFIX + "i";

    // V3 Algorithm constants
    public static final String V3_ALG_AES_GCM = "AES/GCM";
    public static final String V3_ALG_KMS_CONTEXT = "kms+context";
    public static final String V3_ALG_RSA_OAEP_SHA1 = "RSA-OAEP-SHA1";

    public static final String V3_COMPRESSED_AES_GCM = "02";
    public static final String V3_COMPRESSED_KMS_CONTEXT = "12";
    public static final String V3_COMPRESSED_RSA_OAEP_SHA1 = "22";

    public static boolean isV1Format(Map<String, String> metadata) {
        return metadata.containsKey(CONTENT_IV) &&
                metadata.containsKey(ENCRYPTED_DATA_KEY_MATDESC_OR_EC) &&
                //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
                //# If there are multiple mapkeys which are meant to be exclusive, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
                metadata.containsKey(ENCRYPTED_DATA_KEY_V1) &&
                !metadata.containsKey(ENCRYPTED_DATA_KEY_V2) &&
                !metadata.containsKey(ENCRYPTED_DATA_KEY_V3);
    }

    public static boolean isV2Format(Map<String, String> metadata) {
        return metadata.containsKey(CONTENT_CIPHER) &&
                metadata.containsKey(CONTENT_IV) &&
                metadata.containsKey(ENCRYPTED_DATA_KEY_ALGORITHM) &&
                // TODO-Post-Pentest: Objects copied without x-amz-matdesc was able be decrypted by V2 Client.
                //  Should this mapkey be SHOULD instead of MUST?
                // metadata.containsKey(ENCRYPTED_DATA_KEY_MATDESC_OR_EC) &&
                //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
                //# If there are multiple mapkeys which are meant to be exclusive, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
                metadata.containsKey(ENCRYPTED_DATA_KEY_V2) &&
                !metadata.containsKey(ENCRYPTED_DATA_KEY_V1) &&
                !metadata.containsKey(ENCRYPTED_DATA_KEY_V3);
    }


    public static boolean isV3Format(Map<String, String> metadata) {
        return metadata.containsKey(CONTENT_CIPHER_V3) &&
                metadata.containsKey(ENCRYPTED_DATA_KEY_ALGORITHM_V3) &&
                metadata.containsKey(KEY_COMMITMENT_V3) &&
                metadata.containsKey(MESSAGE_ID_V3) &&
                //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
                //# If there are multiple mapkeys which are meant to be exclusive, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.
                metadata.containsKey(ENCRYPTED_DATA_KEY_V3) &&
                !metadata.containsKey(ENCRYPTED_DATA_KEY_V2) &&
                !metadata.containsKey(ENCRYPTED_DATA_KEY_V1);

    }

    /**
     * Compresses a wrapping algorithm name to its V3 format.
     */
    public static String compressWrappingAlgorithm(String algorithmName) {
        switch (algorithmName) {
            //= specification/s3-encryption/data-format/content-metadata.md#v3-only
            //# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval, and vice versa on write.
            case V3_ALG_AES_GCM:
                return V3_COMPRESSED_AES_GCM;
            //= specification/s3-encryption/data-format/content-metadata.md#v3-only
            //# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval, and vice versa on write.
            case V3_ALG_KMS_CONTEXT:
                return V3_COMPRESSED_KMS_CONTEXT;
            //= specification/s3-encryption/data-format/content-metadata.md#v3-only
            //# - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval, and vice versa on write.
            case V3_ALG_RSA_OAEP_SHA1:
                return V3_COMPRESSED_RSA_OAEP_SHA1;
            default:
                throw new S3EncryptionClientException("Unknown wrapping algorithm: " + algorithmName);
        }
    }

    /**
     * Decompresses a V3 format value to its full wrapping algorithm name.
     */
    public static String decompressWrappingAlgorithm(String compressedValue) {
        switch (compressedValue) {
            //= specification/s3-encryption/data-format/content-metadata.md#v3-only
            //# - The wrapping algorithm value "02" MUST be translated to AES/GCM upon retrieval, and vice versa on write.
            case V3_COMPRESSED_AES_GCM:
                return V3_ALG_AES_GCM;
            //= specification/s3-encryption/data-format/content-metadata.md#v3-only
            //# - The wrapping algorithm value "12" MUST be translated to kms+context upon retrieval, and vice versa on write.
            case V3_COMPRESSED_KMS_CONTEXT:
                return V3_ALG_KMS_CONTEXT;
            //= specification/s3-encryption/data-format/content-metadata.md#v3-only
            //# - The wrapping algorithm value "22" MUST be translated to RSA-OAEP-SHA1 upon retrieval, and vice versa on write.
            case V3_COMPRESSED_RSA_OAEP_SHA1:
                return V3_ALG_RSA_OAEP_SHA1;
            default:
                throw new S3EncryptionClientException("Unknown wrapping algorithm value: " + compressedValue);
        }
    }
}
