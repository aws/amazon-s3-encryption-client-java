// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.algorithms;

class AlgorithmConstants {
    /**
     * The maximum number of 16-byte blocks that can be encrypted with a
     * GCM cipher.  Note the maximum bit-length of the plaintext is (2^39 - 256),
     * which translates to a maximum byte-length of (2^36 - 32), which in turn
     * translates to a maximum block-length of (2^32 - 2).
     * <p>
     * Reference: <a href="http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf">
     * NIST Special Publication 800-38D.</a>.
     */
    static final long GCM_MAX_CONTENT_LENGTH_BITS = (1L << 39) - 256;

    /**
     * The Maximum length of the content that can be encrypted in CBC mode.
     */
    static final long CBC_MAX_CONTENT_LENGTH_BYTES = (1L << 55);

    /**
     * The maximum number of bytes that can be securely encrypted per a single key using AES/CTR.
     */
    static final long CTR_MAX_CONTENT_LENGTH_BYTES = -1;
}
