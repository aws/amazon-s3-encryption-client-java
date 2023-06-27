// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
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