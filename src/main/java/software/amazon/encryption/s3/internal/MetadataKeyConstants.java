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
package software.amazon.encryption.s3.internal;

public class MetadataKeyConstants {
    public static final String ENCRYPTED_DATA_KEY_V1 = "x-amz-key";
    public static final String ENCRYPTED_DATA_KEY_V2 = "x-amz-key-v2";
    // This is the name of the keyring/algorithm e.g. AES/GCM or kms+context
    public static final String ENCRYPTED_DATA_KEY_ALGORITHM = "x-amz-wrap-alg";
    public static final String ENCRYPTED_DATA_KEY_CONTEXT = "x-amz-matdesc";

    public static final String CONTENT_IV = "x-amz-iv";
    // This is usually an actual Java cipher e.g. AES/GCM/NoPadding
    public static final String CONTENT_CIPHER = "x-amz-cek-alg";
    public static final String CONTENT_CIPHER_TAG_LENGTH = "x-amz-tag-len";
}
