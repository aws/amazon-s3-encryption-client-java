[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: CC-BY-SA-4.0"

# Keyring Interface

## Overview

Keyrings are responsible for the generation, encryption, and decryption of data keys.

The keyring interface specified in this document describes the interface all keyrings MUST implement.

## Definitions

### Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

### key namespace

A configuration value for a keyring that identifies the grouping or categorization for the wrapping keys that the keyring can access.

The key namespace MUST be a string value.

### key name

A configuration value for a keyring that identifies a single wrapping key within a key namespace.

The key name MUST be a string value.

### key provider ID

An output value returned by a keyring on encrypt as part of an encrypted data key structure that identifies the grouping or categorization for a keyring that can fulfill this decryption contract.

The key provider ID MUST be a binary value and SHOULD be equal to a UTF-8 encoding of the key namespace.

This value MUST NOT be "aws-kms" unless this encrypted data key was produced by the [AWS KMS Keyring](kms-keyring.md).

### key provider info

An output value returned by a keyring on encrypt as part of an encrypted data key structure that provides necessary information for a keyring to fulfill this decryption contract.

The key provider info MUST be a binary value and SHOULD be equal to a UTF-8 encoding of the key name.

## Supported Keyrings

- [AWS KMS Context Keyring](kms-context-keyring.md)
- [AES/GCM Keyring](aes-gcm-keyring.md)
- [RSA-OAEP Keyring](rsa-oaep-keyring.md)
- [Legacy KMS Keyring](./legacy/kms-keyring.md)
- [Legacy AES Wrap Keyring](./legacy/aes-wrap-keyring.md)
- [Legacy RSA/ECB Keyring](./legacy/rsa-ecb-keyring.md)

### Legacy Keyrings

Legacy keyrings only support the [OnDecrypt](#ondecrypt) method.

They are used for backwards compatibility only.

## Interface

### OnEncrypt

This interface takes [encryption materials](structures.md#encryption-materials) as input and MAY modify it with any of the following behaviors:

- [Generate data key](#generate-data-key)
- [Encrypt data key](#encrypt-data-key)

If this keyring attempted any of the above behaviors, and successfully completed those behaviors, it MUST output the modified [encryption materials](structures.md#encryption-materials).

If the keyring did not attempt any of the above behaviors, it MUST fail, and it MUST NOT modify the [encryption materials](structures.md#encryption-materials).

#### Generate Data Key

If the [encryption materials](structures.md#encryption-materials) do not contain a plaintext data key, OnEncrypt MAY generate a data key.
If the encryption materials contain a plaintext data key, OnEncrypt MUST NOT generate a data key.

Generate Data Key MAY modify the following fields in the [encryption materials](structures.md#encryption-materials):

- [plaintext data key](structures.md#plaintext-data-key)

To perform this behavior, the keyring generates a [plaintext data key](structures.md#plaintext-data-key) and sets the resulting plaintext data key on the [encryption materials](structures.md#encryption-materials).

The value of the plaintext data key MUST consist of cryptographically secure (pseudo-)random bits.

Note: If the keyring successfully performs this behavior, this means that the keyring MAY then
perform the [Encrypt Data Key](#encrypt-data-key) behavior.

#### Encrypt Data Key

If the [encryption materials](structures.md#encryption-materials) contain a plaintext data key, OnEncrypt MAY encrypt a data key.
If the encryption materials do not contain a plaintext data key, OnEncrypt MUST NOT encrypt a data key.

Encrypt Data Key MAY modify the following fields in the [encryption materials](structures.md#encryption-materials):

- [encrypted data keys](structures.md#encrypted-data-keys)

To perform this behavior, the keyring creates one or more [encrypted data keys](structures.md#encrypted-data-key) using the plaintext data key from the [encryption materials](structures.md#encryption-materials) as input, and appends the [encrypted data keys](structures.md#encrypted-data-key) to the encrypted data key list in the [encryption materials](structures.md#encryption-materials).

The [encrypted data keys](structures.md#encrypted-data-key) produced by this keyring MUST have [ciphertexts](structures.md#ciphertext) that can be decrypted to the plaintext data key in the [encryption materials](structures.md#encryption-materials).

### OnDecrypt

This interface takes [decryption materials](structures.md#decryption-materials) and a list of [encrypted data keys](structures.md#encrypted-data-key) as input and MAY modify it with the following behavior:

- [Decrypt data key](#decrypt-data-key)

If the decryption materials already contain a plaintext data key, the keyring MUST fail and MUST NOT modify the [decryption materials](structures.md#decryption-materials).

If this keyring attempted the above behavior, and succeeded, it MUST output the modified [decryption materials](structures.md#decryption-materials).

If the keyring did not attempt the above behavior, the keyring MUST fail and MUST NOT modify the [decryption materials](structures.md#decryption-materials).

#### Decrypt Data Key

If the encryption materials do contain a plaintext data key, OnDecrypt MUST NOT decrypt a data key.
If the [decryption materials](structures.md#decryption-materials) do not include a plaintext data key, OnDecrypt MAY decrypt a data key.

The decrypt data key MAY modify the following fields in the [decryption materials](structures.md#decryption-materials):

- [Plaintext data key](structures.md#plaintext-data-key-1)

To perform this behavior, the keyring attempts to retrieve a plaintext data key from the input list of [encrypted data keys](structures.md#encrypted-data-key).
It MUST use the first encrypted data key within the list and ignore any subsequent keys. The Amazon S3 Encryption Client does not support multiple encrypted data keys.

If the keyring is able to successfully get at least one plaintext data key from any [encrypted data key](structures.md#encrypted-data-key) and the [decryption materials](structures.md#decryption-materials) still do not include a plaintext data key, it SHOULD set one resulting plaintext data key on the [decryption materials](structures.md#decryption-materials).

If the keyring is unable to get any plaintext data key using the input [encrypted data keys](structures.md#encrypted-data-key), the keyring MUST NOT update the [decryption materials](structures.md#decryption-materials) and MUST return failure.

## Security Considerations

Keyring implementations SHOULD provide integrity guarantees for the [encrypted data keys](structures.md#encrypted-data-key) they return on [OnEncrypt](#onencrypt) such that tampered versions of those encrypted data keys, if input into [OnDecrypt](#ondecrypt), are overwhelmingly likely to cause a decryption failure (i.e. the chance of a successful decryption in this case is negligible).

Such integrity guarantees SHOULD include the integrity of the [encryption context](structures.md#encryption-context) such that, if the encryption context used as input to OnEncrypt to produce an encrypted data key is different from the encryption context input to OnDecrypt to decrypt that encrypted data key, the decryption is overwhelmingly likely to fail.

Users SHOULD use a keyring that protects wrapping keys and performs cryptographic operations within a secure boundary.
Examples are:

- The built-in [AWS KMS Context Keyring](kms-context-keyring.md), which uses AWS Key Management Service (AWS KMS) customer master keys (CMKs) that never leave AWS KMS plaintext.
- A custom keyring that uses wrapping keys that are stored in your hardware security modules (HSMs)
- A custom keyring protected by another master key service.

The [AES/GCM Keyring](aes-gcm-keyring.md) and [RSA-OAEP Keyring](rsa-oaep-keyring.md) MAY be used, however users should refer to their specification for notes on their respective security considerations.
