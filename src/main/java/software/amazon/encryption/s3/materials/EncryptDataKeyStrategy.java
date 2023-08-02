// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public interface EncryptDataKeyStrategy {
    String keyProviderInfo();

    default boolean isKms(){
        return false;
    }

    default EncryptionMaterials modifyMaterials(EncryptionMaterials materials) {
        return materials;
    }

    default GenerateDataKeyResponse generateDataKey(EncryptionMaterials materials) {
        return null;
    }

    byte[] encryptDataKey(
            SecureRandom secureRandom,
            EncryptionMaterials materials
    ) throws GeneralSecurityException;
}
