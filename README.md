## Amazon S3 Encryption Client

This library provides an S3 client that supports client-side encryption. For more information and detailed instructions
for how to use this library, refer to the 
[Amazon S3 Encryption Client Developer Guide](https://docs.aws.amazon.com/amazon-s3-encryption-client/latest/developerguide/what-is-s3-encryption-client.html).

## Testing
Integration tests are included. To test them, certain environment variables need to be set:

* `AWS_S3EC_TEST_BUCKET` - The bucket to write test values to
* `AWS_S3EC_TEST_KMS_KEY_ID` - The key ID for the KMS key used for KMS tests
* `AWS_S3EC_TEST_KMS_KEY_ALIAS` - An alias for the KMS key used for KMS tests. The alias must reference the key ID above.
* `AWS_REGION` - The region the AWS resources (KMS key, S3 bucket) resides e.g. "us-east-1"

To create these resources, refer to the included CloudFormation template (cfn/S3EC-GitHub-CF-Template).
The IAM Role `S3ECGithubTestRole` SHOULD BE manually customized by you.
Make sure that the repo in the trust policy of the IAM role refers to your fork instead of the `aws` organization.
Also, remove the `ToolsDevelopment` clause of the `S3ECGithubTestRole`'s `AssumeRolePolicyDocument`.
**NOTE**: Your account may incur charges based on the usage of any resources beyond the AWS Free Tier.

If you have forked this repo, there are additional steps required.
You will need to configure your fork's Github Actions settings to be able to run CI:

Under Settings -> Actions -> General -> Workflow permissions, ensure "Read and write permissions" is selected.
Under Settings -> Security -> Secrets and variables -> Actions -> Repository secrets, add new secret:

* `CI_AWS_ACCOUNT_ID` - the AWS account ID which contains the required resources, e.g. 111122223333.

The other values are added as variables (by clicking the "New repository variable" button):

* `CI_AWS_ROLE` - the IAM role to assume during CI, e.g. S3EC-GitHub-test-role. It must exist in the above account and have permission to call S3 and KMS.
* `CI_AWS_REGION` - the AWS region which contains the required resources, e.g. us-west-2.
* `CI_S3_BUCKET` - the S3 bucket to use, e.g. s3ec-github-test-bucket.
* `CI_KMS_KEY_ID` - the short KMS key ID to use, e.g. c3eafb5f-e87d-4584-9400-cf419ce5d782.
* `CI_KMS_KEY_ALIAS` - the KMS key alias to use, e.g. S3EC-Github-KMS-Key. Note that the alias must reference the key ID above.

## Migration

This version of the library supports reading encrypted objects from previous versions.
It also supports writing objects with non-legacy algorithms.
The list of legacy modes and operations is provided below.

However, this version does not support V2's Unencrypted Object Passthrough.
This library can only read encrypted objects from S3,
unencrypted objects MUST be read with the base S3 Client.

### Examples
#### V2 KMS Materials Provider to V3
```java
class Example {
    public static void main(String[] args) {
        // V2
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_WRAPPING_KEY_ID);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();
        
        // V3
        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_WRAPPING_KEY_ID)
                .build();
    }
}
```

#### V2 AES Key Materials Provider to V3
```java
class Example {
    public static void main(String[] args) {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();
        
        // V2
        EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(new EncryptionMaterials(aesKey));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V3
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(aesKey)
                .build();
    }
}
```

#### V2 RSA Key Materials Provider to V3
```java
class Example {
    public static void main(String[] args) {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair rsaKey = keyPairGen.generateKeyPair();
        
        // V2
        EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(new EncryptionMaterials(rsaKey));
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // V3
        S3Client v3Client = S3EncryptionClient.builder()
                .rsaKeyPair(rsaKey)
                .build();
    }
}
```

#### V1 Key Materials Provider to V3
To allow legacy modes (for decryption only), you must explicitly allow them
```java
class Example {
    public static void main(String[] args) {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();
        
        // V1
        EncryptionMaterialsProvider materialsProvider = new StaticEncryptionMaterialsProvider(new EncryptionMaterials(aesKey));
        AmazonS3Encryption v1Client = AmazonS3EncryptionClient.encryptionBuilder()
                .withEncryptionMaterials(materialsProvider)
                .build();

        // V3
        S3Client v3Client = S3EncryptionClient.builder()
                .aesKey(aesKey)
                .enableLegacyUnauthenticatedModes(true) // for enabling legacy content decryption modes
                .enableLegacyWrappingAlgorithms(true) // for enabling legacy key wrapping modes 
                .build();
    }
}
```

### Legacy Algorithms and Modes
#### Content Encryption
* AES/CBC
#### Key Wrap Encryption
* AES
* AESWrap
* RSA-OAEP w/MGF-1 and SHA-256
* RSA
* KMS (without context)
#### Encryption Metadata Storage
* Instruction File

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

