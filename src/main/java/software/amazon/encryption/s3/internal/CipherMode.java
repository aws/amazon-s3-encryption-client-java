// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import javax.crypto.Cipher;

/**
 * A wrapper around Cipher.opMode which models multipart encryption
 * as distinct from "ordinary" encryption.
 */
public enum CipherMode {
    ENCRYPT(Cipher.ENCRYPT_MODE),
    DECRYPT(Cipher.DECRYPT_MODE),
    MULTIPART_ENCRYPT(Cipher.ENCRYPT_MODE);

    private final int _opMode;

    CipherMode(final int opMode) {
        _opMode = opMode;
    }

    public int opMode() {
        return _opMode;
    }

}
