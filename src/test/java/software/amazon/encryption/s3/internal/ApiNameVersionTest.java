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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ApiNameVersionTest {

    private final static String EXPECTED_API_NAME = "AmazonS3Encrypt";
    private final static String EXPECTED_API_MAJOR_VERSION = "3";

    @Test
    public void testApiNameWithVersion() {
        assertEquals(EXPECTED_API_NAME, ApiNameVersion.apiNameWithVersion().name());
        // To avoid having to hardcode versions, just check that we're incrementing from 3
        assertTrue(ApiNameVersion.apiNameWithVersion().version().startsWith(EXPECTED_API_MAJOR_VERSION));
    }
}