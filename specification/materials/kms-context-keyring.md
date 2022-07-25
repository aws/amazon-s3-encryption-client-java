[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: CC-BY-SA-4.0"

# KMS w/Context Keyring

## Overview

A keyring which interacts with AWS Key Management Service (AWS KMS) to create, encrypt, and decrypt data keys  using AWS KMS keys.

## Definitions

### Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

## Interface

MUST implement the [AWS Materials Provider Library Keyring interface](../keyring-interface.md#interface) # TODO

## Initialization

On initialization, the caller:

- MUST provide an AWS KMS key identifier
- MUST provide an AWS KMS SDK client

The AWS KMS key identifier MUST NOT be null or empty.
The AWS KMS key identifier MUST be [a valid identifier](aws-kms-key-arn.md#a-valid-aws-kms-identifier). # TODO
The AWS KMS SDK client MUST NOT be null.

## OnEncrypt

OnEncrypt MUST take [encryption materials](../structures.md#encryption-materials) as input.

If the input [encryption materials](../structures.md#encryption-materials) do not contain a plaintext data key OnEncrypt MUST generate a data key locally.

The keyring MUST call [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) using the configured AWS KMS client.
The keyring MUST AWS KMS Encrypt call with a request constructed as follows:

- `KeyId` MUST be the configured AWS KMS key identifier.
- `PlaintextDataKey` MUST be the plaintext data key in the [encryption materials](../structures.md#encryption-materials).
- `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included in the input [encryption materials](../structures.md#encryption-materials).

If the call to [AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) does not succeed, OnEncrypt MUST fail.

If the Encrypt call succeeds the response’s `KeyId` MUST be [A valid AWS KMS key ARN](aws-kms-key-arn.md#a-valid-aws-kms-arn). If verified, OnEncrypt MUST append a new [encrypted data key](../structures.md#encrypted-data-key) to the encrypted data key list in the [encryption materials](../structures.md#encryption-materials), constructed as follows:

- The [ciphertext](../structures.md#ciphertext) MUST be the response `CiphertextBlob`.
- The [key provider id](../structures.md#key-provider-id) MUST be "kms+context".

If all Encrypt calls succeed, OnEncrypt MUST output the modified [encryption materials](../structures.md#encryption-materials).

## OnDecrypt

OnDecrypt MUST take [decryption materials](../structures.md#decryption-materials) and a list of [encrypted data keys](../structures.md#encrypted-data-key) as input.

If the [decryption materials](../structures.md#decryption-materials) already contained a valid plaintext data key OnDecrypt MUST return an error.

The set of encrypted data keys MUST first be filtered to match this keyring’s configuration. For the encrypted data key to match:

- Its provider ID MUST exactly match the value “kms+context”.

For each encrypted data key in the filtered set, one at a time, the OnDecrypt MUST attempt to decrypt the data key.
If this attempt results in an error, then these errors MUST be collected.

To attempt to decrypt a particular [encrypted data key](../structures.md#encrypted-data-key), OnDecrypt MUST call [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) with the configured AWS KMS client.

When calling [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html), the keyring MUST call with a request constructed as follows:

- `KeyId` MUST be the configured AWS KMS key identifier.
- `CiphertextBlob` MUST be the [encrypted data key ciphertext](../structures.md#ciphertext).
- `EncryptionContext` MUST be the [encryption context](../structures.md#encryption-context) included in the input [decryption materials](../structures.md#decryption-materials).

If the call to [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) succeeds, OnDecrypt verifies:

- The `KeyId` field in the response MUST equal the configured AWS KMS key identifier.

If the response does not satisfy these requirements then an error MUST be collected and the next encrypted data key in the filtered set MUST be attempted.

If the response does satisfy these requirements then OnDecrypt:

- MUST set the plaintext data key on the [decryption materials](../structures.md#decryption-materials) as the response `Plaintext`.
- MUST immediately return the modified [decryption materials](../structures.md#decryption-materials).

If OnDecrypt fails to successfully decrypt any [encrypted data key](../structures.md#encrypted-data-key), then it MUST yield an error that includes all the collected errors.
