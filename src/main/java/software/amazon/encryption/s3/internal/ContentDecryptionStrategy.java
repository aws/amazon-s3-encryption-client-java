// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.materials.DecryptionMaterials;

import java.io.InputStream;

@FunctionalInterface
public interface ContentDecryptionStrategy {
    InputStream decryptContent(ContentMetadata contentMetadata, DecryptionMaterials materials, InputStream ciphertext);
}
