[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: CC-BY-SA-4.0"

# Algorithm Suites (Addendum)

This is an addendum to the algorithm suites present in the AWS Encryption SDK, available [here](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md).
Only additional or changed information is specified here.

## Implementations

- [Java](aws/aws-s3-encryption-client-java/blob/master/src/main/java/software/amazon/encryption/s3/algorithms/AlgorithmSuite.java)

## Definitions

### CBC

Specification: [NIST FIPS 81](https://csrc.nist.gov/csrc/media/publications/fips/81/archive/1980-12-02/documents/fips81.pdf)

Cipher Block Chaining (CBC) is a mode of operation for block ciphers that is semantically secure but doesn't provide any authentication guarantees over the ciphertext, and is vulnerable to adaptive attacks.

If specified to use CBC, the S3EC MUST use CBC with the following specifics:
- The internal block cipher is the encryption algorithm specified by the algorithm suite.

## Supported Algorithm Suites

The following table includes the algorithm suites supported by the S3EC and their encryption settings.
The value `00 00` is reserved and MUST NOT be used as an Algorithm Suite ID in the future.

| Algorithm Suite ID (hex) | Encryption Algorithm | Encryption Algorithm Mode | Encryption Key Length (bits) | IV Length (bits) | Authentication Tag Length (bits) |
|--------------------------|----------------------|---------------------------|------------------------------|------------------|----------------------------------|
| 00 78                    | AES                  | GCM                       | 256                          | 96               | 128                              |
| 00 70                    | AES                  | CBC                       | 256                          | 128              | 0                                |

### Default Algorithm Suite
The default algorithm suite MUST be 0x0078.

#### Supported Encryption Algorithms

- [AES](#aes)

### Encryption Algorithm Mode

The AEAD operation mode used with the encryption algorithm.

The length of the input IV MUST equal the IV length specified by the algorithm suite.
The length of the authentication tag MUST equal the authentication tag length specified by the algorithm suite.

#### Supported Encryption Algorithm Modes

- [GCM](#gcm) - Default
- [CBC](#cbc) - Decrypt Only

### Encryption Key Length

The length of the encryption key used as input to the encryption algorithm.

### IV Length

The length of the initialization vector (IV) used with the encryption algorithm.

### Authentication Tag Length

The length of the authentication tag used with AEAD.

## Security Considerations

### Which algorithm suite should I use?

You should use the default algorithm suite.

AES-CBC is only included for backwards-compatibility.
