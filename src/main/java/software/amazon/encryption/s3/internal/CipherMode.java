/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
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
