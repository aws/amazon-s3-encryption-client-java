package software.amazon.encryption.s3.internal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ApiNameVersionTest {
    public String expectedApiname;
    public String expectedApiVersion;

    @BeforeEach
    void setUp() {
        expectedApiname = "AwsS3Encrypt";
        expectedApiVersion = "unknown";
    }

    @Test
    void testApiNameWithVersion() {
        Assertions.assertEquals(expectedApiname, ApiNameVersion.apiNameWithVersion().name());
        Assertions.assertEquals(expectedApiVersion, ApiNameVersion.apiNameWithVersion().version());
    }
}