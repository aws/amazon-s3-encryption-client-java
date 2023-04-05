// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import java.security.GeneralSecurityException;

public interface DecryptDataKeyStrategy {
    boolean isLegacy();

    String keyProviderInfo();

    byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey)
            throws GeneralSecurityException;
}
