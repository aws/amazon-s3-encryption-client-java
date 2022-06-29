## Amazon S3 Encryption Client

This library provides an S3 client that supports client-side encryption.

## Migration

This version of the library supports reading encrypted objects from previous versions.
It also supports writing objects with non-legacy algorithms.
The list of legacy modes and operations will be provided below.

### Examples
#### V2 KMS Materials Provider to V3 KMS w/ Context Materials Manager and Keyring
```java
class Example {
    public static void main(String[] args) {
        // V2
        EncryptionMaterialsProvider materialsProvider = new KMSEncryptionMaterialsProvider(KMS_WRAPPING_KEY_ID);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();
        
        // V3
        Keyring keyring = KmsContextKeyring.builder()
                .wrappingKeyId(KMS_WRAPPING_KEY_ID)
                .build();

        MaterialsManager materialsManager = new DefaultMaterialsManager(keyring);
        S3Client v3Client = S3EncryptionClient.builder()
                .materialsManager(materialsManager)
                .build();
    }
}
```

#### V2 AES Key Materials Provider to V3 AES/GCM Materials Manager and Keyring
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
        Keyring keyring = AesGcmKeyring.builder()
                .wrappingKey(aesKey)
                .build();

        MaterialsManager materialsManager = new DefaultMaterialsManager(keyring);
        S3Client v3Client = S3EncryptionClient.builder()
                .materialsManager(materialsManager)
                .build();
    }
}
```

#### V2 RSA Key Materials Provider to V3 RSA-OAEP Materials Manager and Keyring
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
        Keyring keyring = RsaOaepKeyring.builder()
                .wrappingKeyPair(rsaKey)
                .build();

        MaterialsManager materialsManager = new DefaultMaterialsManager(keyring);
        S3Client v3Client = S3EncryptionClient.builder()
                .materialsManager(materialsManager)
                .build();
    }
}
```

#### V1 Key Materials Provider to V3 AES/GCM Materials Manager, Legacy AESWrap Keyring, and Keyring
Since legacy algorithms are supported for decryption only, a non-legacy keyring is required for any writes.
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
        // Create the non-legacy keyring first
        Keyring keyring = AesGcmKeyring.builder()
                .wrappingKey(aesKey)
                .build();
        
        // Create the legacy keyring, passing in the non-legacy keyring
        keyring = AesWrapKeyring.builder()
                .wrappingKey(aesKey)
                .nonLegacyKeyring(keyring)
                .build();

        MaterialsManager materialsManager = new DefaultMaterialsManager(keyring);
        S3Client v3Client = S3EncryptionClient.builder()
                .materialsManager(materialsManager)
                .build();
    }
}
```

### Legacy Algorithms and Modes
#### Content Encryption
* AES/CBC
#### Key Wrap Encryption
* AESWrap
* RSA-OAEP w/MGF-1 and SHA-256
* KMS (without context)
#### Encryption Metadata Storage
* Instruction File

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

