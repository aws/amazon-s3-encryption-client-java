// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

/**
 * Prepares the cryptographic materials used to encrypt and decrypt S3 objects.
 * A CryptographicMaterialsManager uses Keyrings to obtain the encryption and decryption materials appropriate for each request.
 */
public interface CryptographicMaterialsManager {
    /**
     * Returns encryption materials appropriate for the given request.
     * @param request the encryption materials request containing encryption context, commitment policy, and other configuration
     * @return encryption materials including plaintext data key, encrypted data keys, algorithm suite, and encryption context
     */
    EncryptionMaterials getEncryptionMaterials(EncryptionMaterialsRequest request);
    
    /**
     * Returns decryption materials appropriate for the given request.
     * @param request the decrypt materials request containing algorithm suite, encrypted data keys, and encryption context
     * @return decryption materials including plaintext data key and encryption context
     */
    DecryptionMaterials decryptMaterials(DecryptMaterialsRequest request);
}
