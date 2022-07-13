[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: CC-BY-SA-4.0"

# Materials Manager Interface

## Overview

The Materials Manager (MM) assembles the cryptographic materials used to encrypt and decrypt S3 blobs.
The MM interface describes the interface that all MMs MUST implement.

## Definitions

### Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

## Supported MMs

The Amazon S3 Encryption Client provides the following built-in MM types:

- [Default MM](default-mm.md)
- [Legacy Decrypt MM](./legacy/legacy-decrypt-mm.md)

Note: A user MAY create their own custom MM.

## Interface

### Inputs

The inputs to the MM are groups of related fields, referred to as:

- [Encryption Materials Request](#encryption-materials-request)
- [Decrypt Materials Request](#decrypt-materials-request)

#### Encryption Materials Request

This is the input to the [get encryption materials](#get-encryption-materials) behavior.

The encryption materials request MUST include the following:

- [Encryption Context](structures.md#encryption-context)
    - The encryption context provided MAY be empty.

The encryption request MAY include the following:

- [Algorithm Suite](algorithm-suites.md)
- Max Plaintext Length
    - This value represents the maximum length of the plaintext to be encrypted using the returned materials.
      The length of the plaintext to be encrypted MUST not be larger than this value.

#### Decrypt Materials Request

This is the input to the [decrypt materials](#decrypt-materials) behavior.

The decrypt materials request MUST include the following:

- [Algorithm Suite](algorithm-suites.md)
- [Encrypted Data Keys](structures.md#encrypted-data-keys)
- [Encryption Context](structures.md#encryption-context)
    - The encryption context provided MAY be empty.

### Behaviors

The MM Interface MUST support the following behaviors:

- [Get Encryption Materials](#get-encryption-materials)
- [Decrypt Materials](#decrypt-materials)

#### Get Encryption Materials

When the MM gets an [encryption materials request](#encryption-materials-request),
it MUST return [encryption materials](structures.md#encryption-materials) appropriate for the request.

The encryption materials returned MUST include the following:

- [Algorithm Suite](algorithm-suites.md)
    - If the encryption materials request contains an algorithm suite, the encryption materials returned SHOULD contain the same algorithm suite.
- Plaintext Data Key
- [Encrypted Data Keys](structures.md#encrypted-data-keys)
    - There MUST be only one encrypted data key, and it MUST correspond to the above plaintext data key.
- [Encryption Context](structures.md#encryption-context)
    - The MM MAY modify the encryption context.

The MM MUST ensure that the encryption materials returned are valid.

- The encryption materials returned MUST follow the specification for [encryption-materials](structures.md#encryption-materials).
- The value of the plaintext data key MUST be non-NULL.
- The plaintext data key length MUST be equal to the [key derivation input length](algorithm-suites.md#key-derivation-input-length).
- The encrypted data keys list MUST contain at least one encrypted data key.

#### Decrypt Materials

When the MM gets a [decrypt materials request](#decrypt-materials-request),
it MUST return [decryption materials](structures.md#decryption-materials) appropriate for the request.

The decryption materials returned MUST include the following:

- Plaintext Data Key
- [Encryption Context](structures.md#encryption-context)
    - The MM MAY modify the encryption context.
    - The operations made on the encryption context on the Get Encryption Materials call SHOULD be inverted on the Decrypt Materials call.
- [Algorithm Suite](algorithm-suites.md)
    - If the decrypt materials request contains an algorithm suite, the decryption materials returned SHOULD contain the same algorithm suite.

The MM MUST ensure that the decryption materials returned are valid.

- The decryption materials returned MUST follow the specification for [decryption-materials](structures.md#decryption-materials).
- The value of the plaintext data key MUST be non-NULL.
- The plaintext data key returned MUST correspond with at least one of the encrypted data keys.
    - The is typically done by constructing a MM that uses keyrings/master keys.

## Customization

The MM is an ideal point for customization and extension.

Example scenarios include:

- Interacting with other MMs
- Using [Keyring(s)](keyring-interface.md)
- Modifying the encryption context
- Managing the signing/verification keys
- Data key Caching
- Providing support for policy enforcement
