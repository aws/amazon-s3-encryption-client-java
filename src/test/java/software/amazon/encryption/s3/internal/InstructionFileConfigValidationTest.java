// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.encryption.s3.S3EncryptionClientException;

public class InstructionFileConfigValidationTest {

    @Test
    public void testBuilderWithBothClientsSet() {
        S3Client syncClient = S3Client.create();
        S3AsyncClient asyncClient = S3AsyncClient.create();

        assertThrows(S3EncryptionClientException.class, () ->
            InstructionFileConfig.builder()
                .instructionFileClient(syncClient)
                .instructionFileAsyncClient(asyncClient)
                .build()
        );
        
        syncClient.close();
        asyncClient.close();
    }

    @Test
    public void testBuilderWithNoClientAndNotDisabled() {
        assertThrows(S3EncryptionClientException.class, () ->
            InstructionFileConfig.builder().build()
        );
    }

    @Test
    public void testBuilderWithClientAndDisabled() {
        S3Client syncClient = S3Client.create();

        assertThrows(S3EncryptionClientException.class, () ->
            InstructionFileConfig.builder()
                .instructionFileClient(syncClient)
                .disableInstructionFile(true)
                .build()
        );
        
        syncClient.close();
    }

    @Test
    public void testBuilderWithPutEnabledButDisabled() {
        assertThrows(S3EncryptionClientException.class, () ->
            InstructionFileConfig.builder()
                .disableInstructionFile(true)
                .enableInstructionFilePutObject(true)
                .build()
        );
    }

    @Test
    public void testValidConfigurations() {
        S3Client syncClient = S3Client.create();
        S3AsyncClient asyncClient = S3AsyncClient.create();

        // Test sync client configuration
        InstructionFileConfig syncConfig = InstructionFileConfig.builder()
            .instructionFileClient(syncClient)
            .enableInstructionFilePutObject(true)
            .build();
        assertTrue(syncConfig.isInstructionFilePutEnabled());

        // Test async client configuration
        InstructionFileConfig asyncConfig = InstructionFileConfig.builder()
            .instructionFileAsyncClient(asyncClient)
            .enableInstructionFilePutObject(false)
            .build();
        assertFalse(asyncConfig.isInstructionFilePutEnabled());

        // Test disabled configuration
        InstructionFileConfig disabledConfig = InstructionFileConfig.builder()
            .disableInstructionFile(true)
            .build();
        assertFalse(disabledConfig.isInstructionFilePutEnabled());
        
        syncClient.close();
        asyncClient.close();
    }

    @Test
    public void testDefaultInstructionFilePutDisabled() {
        S3Client syncClient = S3Client.create();

        // Test that instruction file put is disabled by default
        InstructionFileConfig config = InstructionFileConfig.builder()
            .instructionFileClient(syncClient)
            .build();
        
        assertFalse(config.isInstructionFilePutEnabled());
        syncClient.close();
    }

    @Test
    public void testInstructionFileConfigWithAsyncClient() {
        S3AsyncClient asyncClient = S3AsyncClient.create();

        InstructionFileConfig config = InstructionFileConfig.builder()
            .instructionFileAsyncClient(asyncClient)
            .enableInstructionFilePutObject(true)
            .build();
        
        assertTrue(config.isInstructionFilePutEnabled());
        asyncClient.close();
    }

    @Test
    public void testInstructionFileConfigDisabledState() {
        InstructionFileConfig disabledConfig = InstructionFileConfig.builder()
            .disableInstructionFile(true)
            .build();
        
        assertFalse(disabledConfig.isInstructionFilePutEnabled());
        
        // Test that disabled config doesn't allow put operations
        assertThrows(S3EncryptionClientException.class, () ->
            disabledConfig.putInstructionFile(null, "test content")
        );
        
        // Test that disabled config doesn't allow get operations
        assertThrows(S3EncryptionClientException.class, () ->
            disabledConfig.getInstructionFile(null)
        );
    }
}
