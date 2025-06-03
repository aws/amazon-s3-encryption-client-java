package software.amazon.encryption.s3.examples;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.awssdk.regions.Region;

public class HelloWorldProgramExample {
    public static void main(String[] args) {
        //Create AWS KMS key (go to KMS to do this):
        String kmsKeyId = "arn:aws:kms:us-east-2:597133212884:key/1483518b-144f-48d7-84ce-735ff8d6da98";
        //Think of object as the "plaintext message"
        String object = "Hello World";
        //Created new bucket for this program...had to update permissions to fix bugs
        String bucket = "testing-bucket-hello-world";
        //Object Key: Identifier of object in S3
        String object_key = "hello-world.txt";

        try (S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(kmsKeyId)
                .enableLegacyUnauthenticatedModes(true)
                .region(Region.US_EAST_2)
                .build()) {

            v3Client.putObject(PutObjectRequest.builder()
                    .bucket(bucket)
                    .key(object_key)
                    .build(), RequestBody.fromString(object));

            String output = v3Client.getObjectAsBytes(builder -> builder
                    .bucket(bucket)
                    .key(object_key)
            ).asUtf8String();

            System.out.println("Object stored in S3 is: "+output);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

