package software.amazon.encryption.s3.internal;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class InstructionFileConfigUploadTest {

    @Test
    void uploadInstructionFileWithSetContentLengthSyncClient() {
        // Create a mock for the S3 client
        S3Client mockedS3Client = mock(S3Client.class);
        // The argument captor is used to capture the PutObjectRequest passed to the putObject method
        ArgumentCaptor<PutObjectRequest> instructionFilePutCaptor = ArgumentCaptor.forClass(PutObjectRequest.class);

        // Create the InstructionFileConfig with the mocked S3 client
        InstructionFileConfig instructionFileConfig = InstructionFileConfig.builder()
                .instructionFileClient(mockedS3Client)
                .enableInstructionFilePutObject(true)
                .build();

        // Build some data for the test
        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .key("someKey").build();
        String instructionFileContent = "some content that fakes an instruction file";

        // call the actual method under test
        instructionFileConfig.putInstructionFile(putObjectRequest, instructionFileContent);

        // Verify that the putObject method was called and the captured request has the correct content length
        verify(mockedS3Client).putObject(instructionFilePutCaptor.capture(), any(RequestBody.class));
        assertEquals(instructionFileContent.getBytes().length, instructionFilePutCaptor.getValue().contentLength());
    }

    @Test
    void uploadInstructionFileWithSetContentLengthAsyncClient() {
        // Create a mock for the S3 client
        S3AsyncClient mockedS3Client = mock(S3AsyncClient.class);
        // The async putObject method returns a CompletableFuture, so we need to mock that behavior
        when(mockedS3Client.putObject(any(PutObjectRequest.class), any(AsyncRequestBody.class)))
                .thenReturn(CompletableFuture.completedFuture(null));
        // The argument captor is used to capture the PutObjectRequest passed to the putObject method
        ArgumentCaptor<PutObjectRequest> instructionFilePutCaptor = ArgumentCaptor.forClass(PutObjectRequest.class);

        // Create the InstructionFileConfig with the mocked S3 async client
        InstructionFileConfig instructionFileConfig = InstructionFileConfig.builder()
                .instructionFileAsyncClient(mockedS3Client)
                .enableInstructionFilePutObject(true)
                .build();

        // Build some data for the test
        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .key("someKey").build();
        String instructionFileContent = "some content that fakes an instruction file";

        // call the actual method under test
        instructionFileConfig.putInstructionFile(putObjectRequest, instructionFileContent);

        // Verify that the putObject method was called and the captured request has the correct content length
        verify(mockedS3Client).putObject(instructionFilePutCaptor.capture(), any(AsyncRequestBody.class));
        assertEquals(instructionFileContent.getBytes().length, instructionFilePutCaptor.getValue().contentLength());
    }
}