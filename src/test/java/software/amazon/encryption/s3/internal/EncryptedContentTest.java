// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.core.async.AsyncRequestBody;

public class EncryptedContentTest {

    @Test
    public void testIvAndMessageIdCanBeRetrievedForContentMetadata() {
        // Test data
        byte[] testIv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        byte[] testMessageId = new byte[]{13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28};
        AsyncRequestBody mockRequestBody = AsyncRequestBody.fromString("test content");
        long ciphertextLength = 100L;

        // Create EncryptedContent with IV and Message ID
        EncryptedContent encryptedContent = new EncryptedContent(testIv, testMessageId, mockRequestBody, ciphertextLength);

        // Verify that IV can be retrieved from the encryption process
        byte[] retrievedIv = encryptedContent.iv();
        assertNotNull(retrievedIv, "IV must be retrievable from EncryptedContent");
        assertArrayEquals(testIv, retrievedIv, "Retrieved IV must match the original IV");

        // Verify that Message ID can be retrieved from the encryption process
        byte[] retrievedMessageId = encryptedContent.messageId();
        assertNotNull(retrievedMessageId, "Message ID must be retrievable from EncryptedContent");
        assertArrayEquals(testMessageId, retrievedMessageId, "Retrieved Message ID must match the original Message ID");

        // Verify that retrieved values are defensive copies (not the same reference)
        assertNotSame(testIv, retrievedIv, "IV should be a defensive copy");
        assertNotSame(testMessageId, retrievedMessageId, "Message ID should be a defensive copy");
    }

    @Test
    public void testNullIvAndMessageIdHandling() {
        AsyncRequestBody mockRequestBody = AsyncRequestBody.fromString("test content");
        long ciphertextLength = 100L;

        // Create EncryptedContent with null IV and Message ID
        EncryptedContent encryptedContent = new EncryptedContent(null, null, mockRequestBody, ciphertextLength);

        // Verify that null values are properly handled
        assertNull(encryptedContent.iv(), "Null IV should return null");
        assertNull(encryptedContent.messageId(), "Null Message ID should return null");
    }
}
