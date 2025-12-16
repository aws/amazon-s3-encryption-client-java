package software.amazon.encryption.s3.examples;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.S3AsyncEncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.materials.KmsKeyring;
import software.amazon.encryption.s3.utils.S3EncryptionClientTestResources;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.encryption.s3.utils.S3EncryptionClientTestResources.*;

public class ClientConfigurationExample {

  public static void main(String[] args) {
    CustomClientConfiguration();
    TopLevelClientConfiguration();
    CustomClientConfigurationAsync();
    TopLevelClientConfigurationAsync();
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

    /*
     * Instantiate the wrapped Async S3 client with the default credentials
     * and the region to use with S3.
     * The default S3 Encryption Client uses the async client for
     * operations requiring encryption or decryption.
     * All other operations such as bucket-related operations use the default client,
     * which is configured below.
     */
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
    final S3Client s3Client = S3EncryptionClient.builderV4()
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
    // NOTE: If you use both the "top-level" configuration AND
    // custom configuration such as the above example, the custom client
    // configuration will take precedence.
    final S3Client s3Client = S3EncryptionClient.builderV4()
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

  /**
   * This example demonstrates how to use specific client configuration for
   * the S3 and KMS clients used within the S3 Async Encryption Client.
   */
  public static void CustomClientConfigurationAsync() {
    final String objectKey = appendTestSuffix("custom-client-configuration-example-async");
    final String input = "CustomClientConfigurationExample";
    // Load your AWS credentials from an external source.
    final AwsCredentialsProvider defaultCreds = DefaultCredentialsProvider.create();
    // This example uses two different sets of credentials.
    final AwsCredentialsProvider altCreds = new S3EncryptionClientTestResources.AlternateRoleCredentialsProvider();

    // Instantiate the wrapped (async) S3 client with the default credentials
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

    // Instantiate the S3 Async Encryption Client using the configured clients and keyring.
    final S3AsyncClient s3Client = S3AsyncEncryptionClient.builderV4()
            .wrappedClient(wrappedAsyncClient)
            .keyring(kmsKeyring)
            .build();

    // Use the async client to call putObject and block on its response
    s3Client.putObject(builder -> builder
                    .bucket(BUCKET)
                    .key(objectKey)
                    .build(),
            AsyncRequestBody.fromString(input)).join();

    // Use the async client to call getObject and block on its response
    ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObject(builder -> builder
            .bucket(BUCKET)
            .key(objectKey)
            .build(), AsyncResponseTransformer.toBytes()).join();
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
  public static void TopLevelClientConfigurationAsync() {
    final String objectKey = appendTestSuffix("top-level-client-configuration-async-example");
    final String input = "TopLevelClientConfigurationExample";
    // Load your AWS credentials from an external source.
    final AwsCredentialsProvider creds = new S3EncryptionClientTestResources.AlternateRoleCredentialsProvider();

    // Instantiate the S3 Async Encryption Client via its builder.
    // By passing the creds into the credentialsProvider parameter,
    // the S3EC will use these creds for both S3 and KMS requests.
    // NOTE: If you use both the "top-level" configuration AND
    // custom configuration such as the above example, the custom client
    // configuration will take precedence.
    final S3AsyncClient s3Client = S3AsyncEncryptionClient.builderV4()
            .credentialsProvider(creds)
            .region(Region.of(KMS_REGION.toString()))
            .kmsKeyId(ALTERNATE_KMS_KEY)
            .build();

    // Use the async client to call putObject and block on its response.
    s3Client.putObject(builder -> builder
                    .bucket(BUCKET)
                    .key(objectKey)
                    .build(),
            AsyncRequestBody.fromString(input)).join();

    // Use the async client to call getObject and block on its response.
    ResponseBytes<GetObjectResponse> objectResponse = s3Client.getObject(builder -> builder
            .bucket(BUCKET)
            .key(objectKey)
            .build(), AsyncResponseTransformer.toBytes()).join();
    String output = objectResponse.asUtf8String();
    // Check that the output matches the input.
    assertEquals(input, output);

    // Delete the object.
    deleteObject(BUCKET, objectKey, s3Client);
    // Close the S3 Client.
    s3Client.close();
  }
}
