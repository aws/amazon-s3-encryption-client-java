// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.S3EncryptionClientException;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class AesKeyringTest {

    @Test
    public void testAesKeyringWithNullWrappingKeyFails() {
        assertThrows(S3EncryptionClientException.class, () -> AesKeyring.builder().wrappingKey(null));
    }

    @Test
    public void buildAesKeyringWithNullSecureRandomFails() {
        assertThrows(S3EncryptionClientException.class, () -> AesKeyring.builder().secureRandom(null));
    }

    @Test
    public void buildAesKeyringWithNullDataKeyGeneratorFails() {
        assertThrows(S3EncryptionClientException.class, () -> AesKeyring.builder().dataKeyGenerator(null));
    }
}
