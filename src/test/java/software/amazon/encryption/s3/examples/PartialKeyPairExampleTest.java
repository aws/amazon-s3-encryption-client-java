// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.examples;

import org.junitpioneer.jupiter.RetryingTest;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import static org.junit.jupiter.api.Assertions.fail;

public class PartialKeyPairExampleTest {

    @RetryingTest(3)
    public void testPartialKeyPairExamples() {
        final String bucket = S3EncryptionClientTestResources.BUCKET;
        try {
            PartialKeyPairExample.main(new String[]{bucket});
        } catch (Throwable exception) {
            exception.printStackTrace();
            fail("Partial Key Pair Example Test Failed!!", exception);
        }
    }
}
