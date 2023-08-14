// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public interface EncryptDataKeyStrategy {
    String keyProviderInfo();

    default EncryptionMaterials modifyMaterials(EncryptionMaterials materials) {
        return materials;
    }

    byte[] encryptDataKey(
            SecureRandom secureRandom,
            EncryptionMaterials materials
    ) throws GeneralSecurityException;
}