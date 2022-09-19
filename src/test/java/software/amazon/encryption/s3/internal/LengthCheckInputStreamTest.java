package software.amazon.encryption.s3.internal;

import org.junit.jupiter.api.Test;
import software.amazon.encryption.s3.S3EncryptionClientException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class LengthCheckInputStreamTest {

    private static final String INPUT_STRING = "The quick brown fox jumps over the lazy dog.";
    private static final byte[] INPUT_STRING_BYTES = INPUT_STRING.getBytes(StandardCharsets.UTF_8);
    private static final int INPUT_STRING_BYTES_LENGTH = INPUT_STRING_BYTES.length;

    @Test
    public void illegalLengthTest() {
        final ByteArrayInputStream input = new ByteArrayInputStream(INPUT_STRING_BYTES);
        final int illegalLength = -1;

        try {
            new LengthCheckInputStream(input, illegalLength, LengthCheckInputStream.EXCLUDE_SKIPPED_BYTES);
            fail("Expected exception!");
        } catch (final IllegalArgumentException exception) {
            // expected
        }
    }

    @Test
    public void readWithinLengthTest() {
        final ByteArrayInputStream input = new ByteArrayInputStream(INPUT_STRING_BYTES);
        final LengthCheckInputStream stream = new LengthCheckInputStream(input, INPUT_STRING_BYTES_LENGTH,
                LengthCheckInputStream.EXCLUDE_SKIPPED_BYTES);
        byte[] outputBytes = new byte[INPUT_STRING_BYTES_LENGTH];

        try {
            int readLength = stream.read(outputBytes, 0, INPUT_STRING_BYTES_LENGTH);
            assertEquals(INPUT_STRING, new String(outputBytes));
            assertEquals(INPUT_STRING.getBytes().length, readLength);
        } catch (final IOException exception) {
            fail("IOException during read!" + exception.getMessage());
        }
    }

    @Test
    public void readPastLengthTest() {
        // Set expectedLength below input length to force check
        final int expectedLength = INPUT_STRING_BYTES_LENGTH - 1;
        final ByteArrayInputStream input = new ByteArrayInputStream(INPUT_STRING_BYTES);
        final LengthCheckInputStream stream = new LengthCheckInputStream(input, expectedLength,
                LengthCheckInputStream.EXCLUDE_SKIPPED_BYTES);
        byte[] outputBytes = new byte[INPUT_STRING_BYTES_LENGTH];

        try {
            stream.read(outputBytes, 0, INPUT_STRING_BYTES_LENGTH);
            fail("Expected exception!");
        } catch (final IOException exception) {
            // This exception is not expected
            fail("IOException during read!" + exception.getMessage());
        } catch (final S3EncryptionClientException s3EncryptionClientException) {
            // This exception is expected
        }
    }

    @Test
    public void markResetTest() {
        final ByteArrayInputStream input = new ByteArrayInputStream(INPUT_STRING_BYTES);
        final LengthCheckInputStream stream = new LengthCheckInputStream(input, INPUT_STRING_BYTES_LENGTH,
                LengthCheckInputStream.EXCLUDE_SKIPPED_BYTES);
        byte[] outputBytes = new byte[INPUT_STRING_BYTES_LENGTH];

        try {
            stream.read(outputBytes, 0, INPUT_STRING_BYTES_LENGTH / 2);
            // Mark at halfway point
            stream.mark(INPUT_STRING_BYTES_LENGTH / 2);
            // Read until the end
            stream.read();
            // Reset back to halfway
            stream.reset();
            // Read second half
            stream.read(outputBytes, INPUT_STRING_BYTES_LENGTH / 2, INPUT_STRING_BYTES_LENGTH / 2);
        } catch (final IOException exception) {
            // This exception is not expected
            fail("IOException during read!" + exception.getMessage());
        }
    }

    @Test
    public void skipTest() {
        final ByteArrayInputStream input = new ByteArrayInputStream(INPUT_STRING_BYTES);
        final LengthCheckInputStream stream = new LengthCheckInputStream(input, INPUT_STRING_BYTES_LENGTH,
                LengthCheckInputStream.EXCLUDE_SKIPPED_BYTES);
        byte[] outputBytes = new byte[INPUT_STRING_BYTES_LENGTH];

        try {
            stream.read(outputBytes, 0, INPUT_STRING_BYTES_LENGTH / 2);
            // Mark at halfway point
            stream.mark(INPUT_STRING_BYTES_LENGTH / 2);
            // Skip until the end
            stream.skip(INPUT_STRING_BYTES_LENGTH / 2);
            // Reset back to halfway
            stream.reset();
            // Read second half
            stream.read(outputBytes, INPUT_STRING_BYTES_LENGTH / 2, INPUT_STRING_BYTES_LENGTH / 2);
        } catch (final IOException exception) {
            // This exception is not expected
            fail("IOException during read!" + exception.getMessage());
        }
    }

}
