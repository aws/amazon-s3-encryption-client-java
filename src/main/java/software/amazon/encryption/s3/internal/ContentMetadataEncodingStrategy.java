// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

public interface ContentMetadataEncodingStrategy {

    PutObjectRequest encodeMetadata(EncryptionMaterials materials, byte[] iv, PutObjectRequest putObjectRequest);
    CreateMultipartUploadRequest encodeMetadata(EncryptionMaterials materials, byte[] iv, CreateMultipartUploadRequest createMultipartUploadRequest);

}
