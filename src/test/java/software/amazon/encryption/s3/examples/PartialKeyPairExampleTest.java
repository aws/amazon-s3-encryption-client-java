// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.examples;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

public class PartialKeyPairExampleTest {

    @Test
    public void testPartialKeyPairExamples() {
        final String bucket = S3EncryptionClientTestResources.BUCKET;

        PartialKeyPairExample.main(new String[]{bucket});
    }
}
