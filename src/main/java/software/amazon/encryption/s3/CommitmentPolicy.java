// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

/**
 * Defines the S3 Encryption Client's key commitment behavior during encryption and decryption operations.
 * Key commitment ensures each encrypted object can be decrypted to only a single plaintext by cryptographically binding the data key to the encrypted object.
 * <p>
 * For more information, refer to the <a href=https://docs.aws.amazon.com/amazon-s3-encryption-client/latest/developerguide/concepts.html)>Developer Guide.</a>
 */
public enum CommitmentPolicy {

    //= specification/s3-encryption/key-commitment.md#commitment-policy
    //# When the commitment policy is FORBID_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
    /**
     * This policy forbids the client from encrypting objects with an algorithm suite which supports key commitment.
     * This policy allows decryption of objects using algorithm suites which do not support key commitment. Objects encrypted with key commitment may be decrypted as well.
     * <p>
     * This client will write objects that any v3 client can read and any v4 client can read.
     * This client can read objects written by any v3 or v4 client.
     * This is the default (and only) policy for v3 clients.
     */
    FORBID_ENCRYPT_ALLOW_DECRYPT(false, false),

    //= specification/s3-encryption/key-commitment.md#commitment-policy
    //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
    //= specification/s3-encryption/key-commitment.md#commitment-policy
    //# When the commitment policy is REQUIRE_ENCRYPT_ALLOW_DECRYPT, the S3EC MUST allow decryption using algorithm suites which do not support key commitment.
    /**
     * This policy requires the client to encrypt objects using an algorithm suite which supports key commitment.
     * This policy allows decryption of objects using algorithm suites which do not support key commitment. Objects encrypted with key commitment may be decrypted as well.
     * <p>
     * This client will write objects that any v4 client can read.
     * Only V4 clients and the latest V3 client can read objects written by a client using this policy.
     * This client can read objects written by any V3 or V4 client.
     */
    REQUIRE_ENCRYPT_ALLOW_DECRYPT(true, false),

    //= specification/s3-encryption/key-commitment.md#commitment-policy
    //# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST only encrypt using an algorithm suite which supports key commitment.
    //= specification/s3-encryption/key-commitment.md#commitment-policy
    //# When the commitment policy is REQUIRE_ENCRYPT_REQUIRE_DECRYPT, the S3EC MUST NOT allow decryption using algorithm suites which do not support key commitment.
    /**
     * This policy requires the client to encrypt objects using an algorithm suite which supports key commitment.
     * This policy requires that objects have been encrypted using an algorithm suite which supports key commitment. 
     * <p>
     * This client will write objects that any v4 client can read.
     * Only V4 clients and the latest V3 clients can read objects written by a client using this policy.
     * This client can only read objects written by v4 clients with key commitment enabled.
     * This is the most secure policy and should be used when all objects are encrypted with key commitment.
     */
    REQUIRE_ENCRYPT_REQUIRE_DECRYPT(true, true);

    private final boolean _requiresEncrypt;
    private final boolean _requiresDecrypt;

    CommitmentPolicy(boolean requiresEncrypt, boolean requiresDecrypt) {
        _requiresEncrypt = requiresEncrypt;
        _requiresDecrypt = requiresDecrypt;
    }

    /**
     * Indicates whether this commitment policy requires key commitment for encryption operations.
     *
     * @return {@code true} if encryption must use algorithm suites that support key commitment
     */
    public boolean requiresEncrypt() {
        return _requiresEncrypt;
    }

    /**
     * Indicates whether this commitment policy requires key commitment for decryption operations.
     *
     * @return {@code true} if decryption can only succeed for messages with valid key commitment
     */
    public boolean requiresDecrypt() {
        return _requiresDecrypt;
    }
}
