package software.amazon.encryption.s3.examples;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.materials.KmsKeyring;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.ALTERNATE_KMS_KEY;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.BUCKET;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.KMS_REGION;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.S3_REGION;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.appendTestSuffix;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.deleteObject;

public class ClientConfigurationExample {

  public static void main(String[] args) {
    CustomClientConfiguration();
    TopLevelClientConfiguration();
  }

  /**
   * This example demonstrates how to use specific client configuration for
   * the S3 and KMS clients used within the S3 Encryption Client.
   */
  public static void CustomClientConfiguration() {
    final String objectKey = appendTestSuffix("custom-client-configuration-example");
    final String input = "CustomClientConfigurationExample";
    // Load your AWS credentials from an external source.
    final AwsCredentialsProvider defaultCreds = DefaultCredentialsProvider.create();
    // This example uses two different sets of credentials.
    final AwsCredentialsProvider altCreds = new S3EncryptionClientTestResources.AlternateRoleCredentialsProvider();

    // Instantiate the wrapped S3 client with the default credentials
    // and the region to use with S3.
    final S3Client wrappedClient = S3Client.builder()
      .credentialsProvider(defaultCreds)
      .region(Region.of(S3_REGION.toString()))
      .build();

    // Instantiate the wrapped Async S3 client with the default credentials
    // and the region to use with S3.
    final S3AsyncClient wrappedAsyncClient = S3AsyncClient.builder()
      .credentialsProvider(defaultCreds)
      .region(Region.of(S3_REGION.toString()))
      .build();

    // Instantiate the KMS client with alternate credentials.
    // This client will be used for all KMS requests.
    final KmsClient kmsClient = KmsClient.builder()
      .credentialsProvider(altCreds)
      .region(Region.of(KMS_REGION.toString()))
      .build();

    // Instantiate a KMS Keyring to use with the S3 Encryption Client.
    final KmsKeyring kmsKeyring = KmsKeyring.builder()
      .wrappingKeyId(ALTERNATE_KMS_KEY)
      .kmsClient(kmsClient)
      .build();

    // Instantiate the S3 Encryption Client using the configured clients and keyring.
    final S3Client s3Client = S3EncryptionClient.builder()
      .wrappedClient(wrappedClient)
      .wrappedAsyncClient(wrappedAsyncClient)
      .keyring(kmsKeyring)
      .build();

    // Use the client to call putObject.
    s3Client.putObject(builder -> builder
        .bucket(BUCKET)
        .key(objectKey)
        .build(),
      RequestBody.fromString(input));

    // Use the client to call getObject.
    ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    String output = objectResponse.asUtf8String();
    // Check that the output matches the input.
    assertEquals(input, output);

    // Delete the object.
    deleteObject(BUCKET, objectKey, s3Client);
    // Close the S3 Client.
    s3Client.close();
  }

  /**
   * This example demonstrates how to use a single client configuration for
   * the S3 and KMS clients used within the S3 Encryption Client.
   */
  public static void TopLevelClientConfiguration() {
    final String objectKey = appendTestSuffix("top-level-client-configuration-example");
    final String input = "TopLevelClientConfigurationExample";
    // Load your AWS credentials from an external source.
    final AwsCredentialsProvider creds = new S3EncryptionClientTestResources.AlternateRoleCredentialsProvider();

    // Instantiate the S3 Encryption Client via its builder.
    // By passing the creds into the credentialsProvider parameter,
    // the S3EC will use these creds for both S3 and KMS requests.
    final S3Client s3Client = S3EncryptionClient.builder()
      .credentialsProvider(creds)
      .region(Region.of(KMS_REGION.toString()))
      .kmsKeyId(ALTERNATE_KMS_KEY)
      .build();

    // Use the client to call putObject.
    s3Client.putObject(builder -> builder
        .bucket(BUCKET)
        .key(objectKey)
        .build(),
      RequestBody.fromString(input));

    // Use the client to call getObject.
    ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObjectAsBytes(builder -> builder
      .bucket(BUCKET)
      .key(objectKey)
      .build());
    String output = objectResponse.asUtf8String();
    // Check that the output matches the input.
    assertEquals(input, output);

    // Delete the object.
    deleteObject(BUCKET, objectKey, s3Client);
    // Close the S3 Client.
    s3Client.close();
  }
}
