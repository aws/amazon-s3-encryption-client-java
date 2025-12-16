# S3 Encryption Client v3 to v4 Migration Examples

> **Note:** This directory contains migration-specific examples for users upgrading from v3 to v4. If you're starting fresh with the S3 Encryption Client, see the [code examples](../../../src/examples/java/software/amazon/encryption/s3/examples).

This directory contains examples demonstrating the migration path from S3 Encryption Client v3 to v4, focusing on different commitment policy configurations. For more information, refer to the <a href="https://docs.aws.amazon.com/amazon-s3-encryption-client/latest/developerguide/java-v4-migration.html">Developer Guide</a>.

These examples are for users who have already stored data using the S3 Encryption Client (S3EC) for Java v3 or earlier versions
(or are using implementations of the S3EC in other languages)
and want to migrate their data to use the v4 client and key committing algorithms.
If you are not already using the S3EC, you can simply use the default configuration of the latest version of the S3EC Java
and be sure you are reading and writing objects encrypted using key committing algorithms.

## Directory Structure

- `v3/` - v3 client that writes objects (`PutObject`) encrypted with non-key committing algorithms and reads objects (`GetObject`) encrypted with either key committing or non-key committing algorithms
- `v4/` - v4 client examples with different commitment policies
  - `V4MigrationStep1.java` - v4 client that writes objects encrypted with non-key committing algorithms and reads objects encrypted with either key committing or non-key committing algorithms
  - `V4MigrationStep2.java` - v4 client that writes objects encrypted with **key committing algorithms** and reads objects encrypted with either key committing or non-key committing algorithms
  - `V4MigrationStep3.java` - v4 client that writes objects encrypted with key committing algorithms and reads objects encrypted with **only key committing algorithms**

## Running the Examples

Each example is a standalone Java program that can be run using Maven:

```bash
# V3 baseline
cd v3
mvn exec:java -Dexec.args="<bucket-name> <object-key> <kms-key-id> <region>"

# V4 examples
cd ../v4
mvn exec:java -Dexec.mainClass="software.amazon.encryption.s3.examples.migration.v4.V4MigrationStep1" -Dexec.args="<bucket-name> <object-key> <kms-key-id> <region>"

mvn exec:java -Dexec.mainClass="software.amazon.encryption.s3.examples.migration.v4.V4MigrationStep2" -Dexec.args="<bucket-name> <object-key> <kms-key-id> <region>"

mvn exec:java -Dexec.mainClass="software.amazon.encryption.s3.examples.migration.v4.V4MigrationStep3" -Dexec.args="<bucket-name> <object-key> <kms-key-id> <region>"
```

## Key Commitment Policies

The examples demonstrate different commitment policies that dictate the support algorithm types on encrypt and decrypt:

- **FORBID_ENCRYPT_ALLOW_DECRYPT**: Does not use key commitment on encrypt (`PutObject`), can decrypt objects (`GetObject`) with or without key commitment
- **REQUIRE_ENCRYPT_ALLOW_DECRYPT**: Uses key commitment on encrypt, can decrypt objects with or without key commitment
- **REQUIRE_ENCRYPT_REQUIRE_DECRYPT**: Uses key commitment on encrypt, can only decrypt objects that also use key commitment

## Prerequisites

- Java 8 or later
- AWS credentials configured
- S3 bucket for testing
- KMS key for encryption
