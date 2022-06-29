[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: CC-BY-SA-4.0"

# Algorithm Suites

## Implementations

- [Java](aws/aws-s3-encryption-client-java/blob/master/src/main/java/software/amazon/encryption/s3/algorithms/AlgorithmSuite.java)

## Overview

An algorithm suite is a collection of cryptographic algorithms and related values.
The algorithm suite defines the behaviors the Amazon S3 Encryption Client (S3EC) MUST follow for cryptographic operations.

## Definitions

### Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

### AES

Specification: [NIST FIPS 297](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

The Advanced Encryption Standard (AES) is a symmetric block cipher encryption algorithm.

### CBC

Specification: [NIST FIPS 81](https://csrc.nist.gov/csrc/media/publications/fips/81/archive/1980-12-02/documents/fips81.pdf)

Cipher Block Chaining (CBC) is a mode of operation for block ciphers that is semantically secure but doesn't provide any authentication guarantees over the ciphertext, and is vulnerable to adaptive attacks.

If specified to use CBC, the S3EC MUST use CBC with the following specifics:
- The internal block cipher is the encryption algorithm specified by the algorithm suite.

### GCM

Specification: [NIST Special Publication 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

Galois/Counter Mode is a mode of operation for block ciphers that provides authenticated encryption with additional data (AEAD).

If specified to use GCM, the S3EC MUST use GCM with the following specifics:
- The internal block cipher is the encryption algorithm specified by the algorithm suite.

## Supported Algorithm Suites

The following table includes the algorithm suites supported by the S3EC and their encryption settings.
The value `00 00` is reserved and MUST NOT be used as an Algorithm Suite ID in the future.

| Algorithm Suite ID (hex) | Encryption Algorithm | Encryption Algorithm Mode | Encryption Key Length (bits) | IV Length (bits) | Authentication Tag Length (bits) |
|--------------------------| -------------------- |---------------------------|------------------------------|------------------|----------------------------------|
| 00 78                    | AES                  | GCM                       | 256                          | 96               | 128                              |
| 00 70                    | AES                  | CBC                       | 256                          | 128              | 0                                |


## Structure

The fields described below are REQUIRED to be specified by algorithm suites, unless otherwise specified.

### Algorithm Suite ID

A 2-byte hex value that uniquely identifies an algorithm suite.

### Encryption Algorithm

The block cipher encryption algorithm.

The length of the input encryption key MUST equal the [encryption key length](#encryption-key-length) specified by the algorithm suite.

#### Supported Encryption Algorithms

- [AES](#aes)

### Encryption Algorithm Mode

The AEAD operation mode used with the encryption algorithm.

The length of the input IV MUST equal the IV length specified by the algorithm suite.
The length of the authentication tag MUST equal the authentication tag length specified by the algorithm suite.

#### Supported Encryption Algorithm Modes

- [GCM](#gcm)
- [CBC](#cbc) - Decrypt Only

### Encryption Key Length

The length of the encryption key used as input to the encryption algorithm.

### IV Length

The length of the initialization vector (IV) used with the encryption algorithm.

### Authentication Tag Length

The length of the authentication tag used with AEAD.

### Encryption Key Derivation Algorithm

This key derivation algorithm defines what key derivation function (KDF) to use for encryption key generation.
The specified KDF algorithm MUST be used to generate the encryption algorithm encryption key input.

#### Supported Key Commitment Values

- True
- False

## Security Considerations

### Which algorithm suite should I use?

You should use the default algorithm suite.

AES-CBC is only included for backwards-compatibility.
