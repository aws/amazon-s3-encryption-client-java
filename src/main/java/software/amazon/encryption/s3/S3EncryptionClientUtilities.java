/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package software.amazon.encryption.s3;

import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;

import java.util.List;
import java.util.stream.Collectors;

/**
 * This class contains that which can be shared between the default S3 Encryption
 * Client and its Async counterpart.
 */
public class S3EncryptionClientUtilities {

    public static final String INSTRUCTION_FILE_SUFFIX = ".instruction";

    /**
     * For a given DeleteObjectsRequest, return a list of ObjectIdentifiers
     * representing the corresponding instruction files to delete.
     * @param request a DeleteObjectsRequest
     * @return the list of ObjectIdentifiers for instruction files to delete
     */
    static List<ObjectIdentifier> instructionFileKeysToDelete(final DeleteObjectsRequest request) {
        return request.delete().objects().stream()
                .map(o -> o.toBuilder().key(o.key() + INSTRUCTION_FILE_SUFFIX).build())
                .collect(Collectors.toList());
    }
}
