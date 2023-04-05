// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.materials.EncryptionMaterials;

import java.util.Map;

@FunctionalInterface
public interface ContentMetadataEncodingStrategy {

    Map<String, String> encodeMetadata(EncryptionMaterials materials, byte[] iv,
                                              Map<String, String> metadata);
}
