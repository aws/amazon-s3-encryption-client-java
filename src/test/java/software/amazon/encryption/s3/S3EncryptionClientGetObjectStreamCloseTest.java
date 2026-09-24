// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

/**
 * Pins the contract that {@link S3EncryptionClient#getObject} relies on to decide whether to close
 * the response stream: buffering transformers do not need the connection left open (so the client
 * closes the stream and avoids the leak), while streaming transformers do (the caller closes it).
 */
public class S3EncryptionClientGetObjectStreamCloseTest {

    @Test
    public void bufferingTransformersDoNotNeedConnectionLeftOpen() throws IOException {
        assertFalse(ResponseTransformer.<GetObjectResponse>toBytes().needsConnectionLeftOpen());

        File tempFile = File.createTempFile("s3ec-close-test", ".tmp");
        tempFile.delete(); // toFile requires the file to not already exist
        tempFile.deleteOnExit();
        assertFalse(ResponseTransformer.<GetObjectResponse>toFile(tempFile.toPath()).needsConnectionLeftOpen());
    }

    @Test
    public void streamingTransformerNeedsConnectionLeftOpen() {
        assertTrue(ResponseTransformer.<GetObjectResponse>toInputStream().needsConnectionLeftOpen());
    }
}
