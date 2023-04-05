// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

public interface CryptographicMaterialsManager {
    EncryptionMaterials getEncryptionMaterials(EncryptionMaterialsRequest request);
    DecryptionMaterials decryptMaterials(DecryptMaterialsRequest request);
}
