package software.amazon.encryption.s3.internal;

import org.junit.jupiter.api.RepeatedTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ApiNameVersionTest {

    private final static String EXPECTED_API_NAME = "AmazonS3Encrypt";
    private final static String EXPECTED_API_VERSION = "unknown";

    @RepeatedTest(10)
    public void testApiNameWithVersion() {
        assertEquals(EXPECTED_API_NAME, ApiNameVersion.apiNameWithVersion().name());
        assertEquals(EXPECTED_API_VERSION, ApiNameVersion.apiNameWithVersion().version());
    }
}