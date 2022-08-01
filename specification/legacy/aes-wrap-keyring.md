[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: CC-BY-SA-4.0"

# AESWrap Keyring

## Overview

A legacy keyring which does AESWrap decryption of data keys using a local wrapping key.

## Definitions

### Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

### AESWrap

The AES key wrap algorithm is designed to wrap or encrypt key data.

Advanced Encryption Standard (AES) Specification: [NIST FIPS 297](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

AESWrap Specification: [RFC 3394](https://datatracker.ietf.org/doc/html/rfc3394)

## Initialization

On keyring initialization, the caller MUST provide the following:

- [Wrapping Key](#wrapping-key)

The caller MAY provide the following:

- [Data Key Generator](data-key-generator-interface.md)

### Wrapping Key

The AES key input to be used with the configured [wrapping algorithm](#wrapping-algorithm) to encrypt plaintext data keys.

The wrapping key MUST be a secret value consisting of cryptographically secure pseudo-random bytes.
It MUST be randomly generated from a cryptographically secure entropy source.
The length of the wrapping key MUST be 256.

### Wrapping Algorithm

The algorithm to be used with the configured [wrapping key](#wrapping-key) to encrypt plaintext data keys.

The keyring MUST support the following algorithm configurations:

- AESWrap with key size 256 bits, IV/nonce length 16 bytes, and tag length 0 bytes

Initialization MUST fail if the length of the [wrapping key](#wrapping-key) does not match the length specified by the wrapping algorithm.

## Structure

### Key Namespace
The key namespace MUST be "AESWrap".

### Key Provider Id
The key provider id MUST be the key namespace.

### Key Provider Information
The key provider information SHALL NOT be used.

### Ciphertext

This structure is a sequence of bytes as output directly from the [AESWrap](#aeswrap) algorithm.

#### Encrypted Key

The ciphertext returned by the AESWrap encryption of the plaintext data key.

## Operation

### OnEncrypt

OnEncrypt MUST take [encryption materials](structures.md#encryption-materials) as input.
OnEncrypt MUST throw an exception for all calls.

### OnDecrypt

OnDecrypt MUST take [decryption materials](structures.md#decryption-materials) and a list of [encrypted data keys](structures.md#encrypted-data-key) as input.

If the decryption materials already contain a plaintext data key, the keyring MUST fail and MUST NOT modify the [decryption materials](structures.md#decryption-materials).

The keyring MUST perform the following actions on each [encrypted data key](structures.md#encrypted-data-key) in the input encrypted data key list, serially, until it successfully decrypts one.

For each [encrypted data key](structures.md#encrypted-data-key), the keyring MUST first attempt to deserialize the [serialized ciphertext](#ciphertext) to obtain the [encrypted key](#encrypted-key).

The keyring attempts to decrypt the encrypted data key if and only if the following is true:

- The [ciphertext](#ciphertext) MUST be successfully deserialized.
- The key provider ID of the encrypted data key MUST have a value equal to this keyring's [key namespace](./keyring-interface.md#key-namespace).

If decrypting, the keyring uses AESWrap with the following specifics:

- It MUST use the [encrypt key](#encrypted-key) obtained from deserialization as the AESWrap input ciphertext.
- It MUST use this keyring's [wrapping key](#wrapping-key) as the AESWrap cipher key.

If a decryption succeeds, this keyring MUST add the resulting plaintext data key to the decryption materials and return the modified materials.

If no decryption succeeds, the keyring MUST fail and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
