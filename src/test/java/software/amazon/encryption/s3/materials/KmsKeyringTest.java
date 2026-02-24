// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.S3EncryptionClientException;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class KmsKeyringTest {

    @RetryingTest(3)
    public void buildKmsKeyringWithNullSecureRandomFails() {
        assertThrows(S3EncryptionClientException.class, () -> KmsKeyring.builder().secureRandom(null));
    }

    @RetryingTest(3)
    public void buildKmsKeyringWithNullDataKeyGeneratorFails() {
        assertThrows(S3EncryptionClientException.class, () -> KmsKeyring.builder().dataKeyGenerator(null));
    }

}
