// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

@FunctionalInterface
public interface ContentMetadataDecodingStrategy {
    ContentMetadata decodeMetadata(GetObjectRequest request, GetObjectResponse response);
}
