[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: CC-BY-SA-4.0"

# Keyring Interface (Addendum)

This is an addendum to the keyring interface present in the AWS Encryption SDK, available [here](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md).
Only additional or changed information is specified here.

## Overview

Keyrings are responsible for the generation, encryption, and decryption of data keys.

The keyring interface specified in this document describes the interface all keyrings MUST implement.

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

## Security Considerations

Users SHOULD use a keyring that protects wrapping keys and performs cryptographic operations within a secure boundary.
Examples are:

- The built-in [AWS KMS Context Keyring](kms-context-keyring.md), which uses AWS Key Management Service (AWS KMS) customer master keys (CMKs) that never leave AWS KMS plaintext.
- A custom keyring that uses wrapping keys that are stored in your hardware security modules (HSMs)
- A custom keyring protected by another master key service.

The [AES/GCM Keyring](aes-gcm-keyring.md) and [RSA-OAEP Keyring](rsa-oaep-keyring.md) MAY be used, however users should refer to their specification for notes on their respective security considerations.
