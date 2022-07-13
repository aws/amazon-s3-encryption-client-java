[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: CC-BY-SA-4.0"

# AES/GCM Keyring

## Overview

A keyring which does AES-GCM encryption and decryption of data keys using a local wrapping key.

## Definitions

### Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

### AES-GCM

Advanced Encryption Standard in Galois/Counter Mode (AES-GCM) is an Authenticated Encryption with Associated Data (AEAD) cipher.

Advanced Encryption Standard (AES) Specification: [NIST FIPS 297](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

Galois/Counter Mode (GCM) Specification: [NIST Special Publication 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

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

- AES/GCM with key size 256 bits, IV/nonce length 12 bytes, and tag length 16 bytes

Initialization MUST fail if the length of the [wrapping key](#wrapping-key) does not match the length specified by the wrapping algorithm.

## Structure

### Key Namespace
The key namespace MUST be "AES/GCM".

### Key Provider Id
The key provider id MUST be the key namespace.

### Key Provider Information
The key provider information SHALL NOT be used.

### Ciphertext

This structure is a sequence of bytes in big-endian format to be used as the [ciphertext](structures.md#ciphertext) field in [encrypted data keys](structures.md#encrypted-data-key) produced by raw AES keyrings.

The following table describes the fields that form the ciphertext for this keyring.
The bytes are appended in the order shown.

| Field         | Length (bytes)                      | Interpreted as |
|---------------|-------------------------------------|----------------|
| Nonce         | 12                                  | Bytes          |
| Encrypted Key | length of AES-GCM ciphertext output | Bytes          |

#### Nonce

The nonce used to initialize the AES-GCM cipher.
(This may also be referred to as an IV).

#### Encrypted Key

The ciphertext returned by the AES-GCM encryption of the plaintext data key.

## Operation

### OnEncrypt

OnEncrypt MUST take [encryption materials](structures.md#encryption-materials) as input.

If the [encryption materials](structures.md#encryption-materials) do not contain a plaintext data key, OnEncrypt MUST generate a random plaintext data key and set it on the [encryption materials](structures.md#encryption-materials).

The keyring MUST encrypt the plaintext data key in the [encryption materials](structures.md#encryption-materials) using AES-GCM.

The keyring uses AES-GCM with the following specifics:

- It MUST use the serialized [algorithm suite cipher name](algorithm-suites.md#cipher-name) as the additional authenticated data (AAD).
- It MUST use this keyring's [wrapping key](#wrapping-key) as the AES-GCM cipher key.
- It MUST use a cryptographically random generated nonce/IV of length specified by this keyring's [wrapping algorithm](#wrapping-algorithm).
- It MUST use an authentication tag of length specified by this keyring's [wrapping algorithm](#wrapping-algorithm).

Based on the ciphertext output of the AES-GCM decryption, the keyring MUST construct an [encrypted data key](structures.md#encrypted-data-key) with the following specifics:

- The [nonce](#nonce) is the nonce used with the wrapping cipher.
- The [ciphertext](structures.md#ciphertext) is serialized as the [AES keyring ciphertext](#ciphertext).

The keyring MUST append the constructed encrypted data key to the encrypted data key list in the [encryption materials](structures.md#encryption-materials).

OnEncrypt MUST output the modified [encryption materials](structures.md#encryption-materials).

### OnDecrypt

OnDecrypt MUST take [decryption materials](structures.md#decryption-materials) and a list of [encrypted data keys](structures.md#encrypted-data-key) as input.

If the decryption materials already contain a plaintext data key, the keyring MUST fail and MUST NOT modify the [decryption materials](structures.md#decryption-materials).

The keyring MUST perform the following actions on each [encrypted data key](structures.md#encrypted-data-key) in the input encrypted data key list, serially, until it successfully decrypts one.

For each [encrypted data key](structures.md#encrypted-data-key), the keyring MUST first attempt to deserialize the [serialized ciphertext](#ciphertext) to obtain the [encrypted key](#encrypted-key) and [nonce](#nonce).

The keyring attempts to decrypt the encrypted data key if and only if the following is true:

- The [ciphertext](#ciphertext) MUST be successfully deserialized.
- The key provider ID of the encrypted data key MUST have a value equal to this keyring's [key namespace](./keyring-interface.md#key-namespace).

If decrypting, the keyring uses AES-GCM with the following specifics:

- It MUST use the [encrypt key](#encrypted-key) obtained from deserialization as the AES-GCM input ciphertext.
- It MUST use this keyring's [wrapping key](#wrapping-key) as the AES-GCM cipher key.
- It MUST use the [nonce](#nonce) obtained from deserialization as the AES-GCM nonce.
- It MUST use the serialized [algorithm suite cipher name](algorithm-suites.md#cipher-name) as the additional authenticated data (AAD).

If a decryption succeeds, this keyring MUST add the resulting plaintext data key to the decryption materials and return the modified materials.

If no decryption succeeds, the keyring MUST fail and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
