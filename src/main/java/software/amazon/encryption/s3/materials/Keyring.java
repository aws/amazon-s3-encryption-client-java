// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import java.util.List;

//= specification/s3-encryption/materials/keyrings.md#interface
//= type=implication
//# The Keyring interface and its operations SHOULD adhere to the naming conventions of the implementation language.
/**
 * Keyring defines the interface for wrapping data keys. A {@link CryptographicMaterialsManager} will use
 * keyrings to encrypt and decrypt data keys.
 */
public interface Keyring {
    //= specification/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The Keyring interface and its operations SHOULD adhere to the naming conventions of the implementation language.
    //= specification/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The Keyring interface MUST include the OnEncrypt operation.
    //= specification/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnEncrypt operation MUST accept an instance of EncryptionMaterials as input.
    //= specification/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnEncrypt operation MUST return an instance of EncryptionMaterials as output.
    EncryptionMaterials onEncrypt(final EncryptionMaterials materials);
    //= specification/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The Keyring interface and its operations SHOULD adhere to the naming conventions of the implementation language.
    //= specification/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The Keyring interface MUST include the OnDecrypt operation.
    //= specification/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnDecrypt operation MUST accept an instance of DecryptionMaterials and a collection of EncryptedDataKey instances as input.
    //= specification/s3-encryption/materials/keyrings.md#interface
    //= type=implication
    //# The OnDecrypt operation MUST return an instance of DecryptionMaterials as output.
    DecryptionMaterials onDecrypt(final DecryptionMaterials materials, final List<EncryptedDataKey> encryptedDataKeys);
}
