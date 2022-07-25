[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: CC-BY-SA-4.0"

# Default Cryptographic Materials Manager

## Overview

The Default Cryptographic Materials Manager (CMM) is a built-in implementation of the [CMM interface](cmm-interface.md) provided by the Amazon S3 Encryption Client.

It is used by default to wrap a keyring.

## Definitions

### Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOCMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

## Initialization

On default CMM initialization, the caller MUST provide the following value:

- [Keyring](#keyring)

### Keyring

The [keyring](keyring-interface.md) this CMM uses to [get encryption materials](#get-encryption-materials) or [decrypt materials](#decrypt-materials).

## Behaviors

### Get Encryption Materials

- If the [encryption materials request](cmm-interface.md#encryption-materials-request) does not contain an algorithm suite, the operation MUST add the [default algorithm suite](algorithm-suites.md#default-algorithm-suite) as the algorithm suite in the encryption materials returned.
- If the [encryption materials request](cmm-interface.md#encryption-materials-request) does contain an algorithm suite, the encryption materials returned MUST contain the same algorithm suite.

On each call to Get Encryption Materials, the default CMM MUST make a call to its [keyring's](#keyring)[On Encrypt](keyring-interface.md#onencrypt) operation.

The default CMM MUST return the [encryption materials](structures.md#encryption-materials) returned from the keyring's OnEncrypt operation.

### Decrypt Materials

On each call to Decrypt Materials, the default CMM MUST make a call to its [keyring's](#keyring)[On Decrypt](keyring-interface.md#ondecrypt) operation.

The default CMM MUST return the [decrypt materials](structures.md#decryption-materials) returned from the keyring's OnDecrypt operation.
