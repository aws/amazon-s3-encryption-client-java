package software.amazon.encryption.s3.examples;

import org.junitpioneer.jupiter.RetryingTest;

import static org.junit.jupiter.api.Assertions.fail;

public class ClientConfigurationExampleTest {
  @RetryingTest(3)
  public void testClientConfigurationExamples() {
      try {
          ClientConfigurationExample.main(new String[0]);
      } catch (Throwable exception) {
          exception.printStackTrace();
          fail("Client Configuration Example Test Failed!!", exception);
      }
  }
}
