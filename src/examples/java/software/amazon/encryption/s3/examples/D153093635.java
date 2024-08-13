package software.amazon.encryption.s3.examples;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DefaultCryptoMaterialsManager;
import software.amazon.encryption.s3.materials.KmsKeyring;

import java.io.InputStream;

public class D153093635 {

    public static void D153093635() {
        S3Client s3Client = S3Client.builder()
                .region(Region.US_WEST_2)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();

        S3AsyncClient asyncs3Client = S3AsyncClient.builder()
                .region(Region.US_WEST_2)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();

        KmsClient kmsClient = KmsClient.builder()
                .region(Region.US_WEST_2)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();

        KmsKeyring kmsKeyring = KmsKeyring.builder()
                .kmsClient(kmsClient)
                .wrappingKeyId("arn:aws:kms:us-west-2:258734353472:key/15460d61-f434-4627-8fd6-d531b334b13a")
                .build();

        CryptographicMaterialsManager kmsCryptoMaterialsManager =
                DefaultCryptoMaterialsManager.builder()
                        .keyring(kmsKeyring)
                        .build();

        S3Client v3Client = S3EncryptionClient.builder()
                .wrappedClient(s3Client)
                .wrappedAsyncClient(asyncs3Client)
                .cryptoMaterialsManager(kmsCryptoMaterialsManager)
                .enableLegacyUnauthenticatedModes(true)
                .enableLegacyWrappingAlgorithms(true)
                .build();

        String bucketName = "lucmcdon-s3ec-test-bucket-us-west-2";
        String key = "sample-object2.txt";
        String sampleData = "This is a sample data to be written to S3.";

        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(bucketName)
                .key(key)
                .build();

        v3Client.putObject(putObjectRequest, RequestBody.fromString(sampleData));
        System.out.println("Sample data written to S3 bucket: " + bucketName + "/" + key);

        // Get the first 10 bytes of the object
        GetObjectRequest rangedGetRequest = GetObjectRequest.builder()
                .bucket(bucketName)
                .key(key)
                // acutal object size is 42 bytes, but due to padding, 16 bytes are added and the length in S3 becomes 58.
                .range("bytes=42-58")
                .build();

        int i = 42;
        try (InputStream is = v3Client.getObject(rangedGetRequest)) {
            while (is.read() != -1) {
                i++;
            }
        } catch (Exception e) {
        }

        System.out.println("length = " + i);
    }

}
