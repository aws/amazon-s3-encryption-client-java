[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: CC-BY-SA-4.0"

# Structures

## Definitions

### Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

## Overview

This document includes the specifications for common structures referenced throughout the Amazon S3 Encryption Client specification.
These structures define a group of related fields that MUST hold certain properties.
Wherever these structures are referenced in this specification, implementations MUST ensure that all properties of a structure's fields are upheld.

Note that this specification does not specify how these structures should be represented or passed throughout the Amazon S3 Encryption Client framework.
While these structures will usually be represented as objects, lower level languages MAY represent these fields in a less strictly defined way as long as all field properties are still upheld.

Structures defined in this document:

- [Encrypted Data Key](#encrypted-data-key)
- [Encryption Context](#encryption-context)
- [Encryption Materials](#encryption-materials)
- [Decryption Materials](#decryption-materials)

### Encrypted Data Key

#### Structure

An encrypted data key comprises the following fields:

- [Key Provider ID](#key-provider-id)
- [Key Provider Information](#key-provider-information)
- [Ciphertext](#ciphertext)

Note: "Encrypted" is a misnomer here, as the process by which a key provider may obtain the plaintext data key from the ciphertext and vice versa does not have to be an encryption and decryption cipher.
This specification uses the terms "encrypt" and "decrypt" for simplicity, but the actual process by which a key provider obtains the plaintext data key from the ciphertext and vice versa MAY be any reversible operation, though we expect that most will use encryption.

##### Key Provider ID

The [key provider ID](keyring-interface.md#key-provider-id) value for the keyring that wrote this encrypted data key.

##### Key Provider Information

The [key provider info](keyring-interface.md#key-provider-info) value for the keyring that wrote this encrypted data key.

##### Ciphertext

An opaque value from which an appropriate key provider can obtain the plaintext data key.

Some key provider MUST be capable of deterministically obtaining the plaintext key from the ciphertext.

Most commonly this is an encrypted form of the plaintext data key.
Alternatively, it could be the public input to a KDF that derives the plaintext data key or an identifier into a key store that will return the plaintext data key.

### Encryption Context

#### Structure

The encryption context is a key-value mapping of arbitrary, non-secret, UTF-8 encoded strings.
It is used during [encryption](../client-apis/encrypt.md) and [decryption](../client-apis/decrypt.md) to provide additional authenticated data (AAD).

Users SHOULD use the encryption context to store:

- Non-secret data that MUST remain associated with the [message](../data-format/message.md) ciphertext.
- Data that is useful in logging and tracking, such as data about the file type, purpose, or ownership.

Users MUST NOT use the encryption context to store secret data.

### Encryption Materials

#### Structure

Encryption materials are a structure containing materials needed for [encryption](../client-apis/encrypt.md).
This structure MAY include any of the following fields:

- [Algorithm Suite](#algorithm-suite)
- [Encrypted Data Keys](#encrypted-data-keys)
- [Encryption Context](#encryption-context-1)
- [Plaintext Data Key](#plaintext-data-key)

##### Algorithm Suite

The [algorithm suite](algorithm-suites.md) to be used for [encryption](../client-apis/encrypt.md).

##### Encrypted Data Keys

A list of the [encrypted data keys](#encrypted-data-key) that correspond to the plaintext data key.

The [ciphertext](#ciphertext) of each encrypted data key in this list MUST be an opaque form of the plaintext data key from this set of encryption materials.

If the plaintext data key is not included in this set of encryption materials, this list MUST be empty.

##### Encryption Context

The [encryption context](#encryption-context) associated with this [encryption](../client-apis/encrypt.md).

##### Plaintext Data Key

A data key to be used as input for [encryption](../client-apis/encrypt.md).

The plaintext data key MUST:

- Fit the specification for the [key derivation algorithm](algorithm-suites.md#key-derivation-algorithm) included in this decryption material's [algorithm suite](#algorithm-suite).
- Consist of cryptographically secure (pseudo-)random bits.
- Be kept secret.

The plaintext data key SHOULD be stored as immutable data.

The plaintext data key SHOULD offer an interface to zero the plaintext data key.

##### Signing Key

The key to be used as the signing key for signature verification during [encryption](../client-apis/encrypt.md).

The value of this key MUST be kept secret.

### Decryption Materials

#### Structure

Decryption materials are a structure containing materials needed for [decryption](../client-apis/decrypt.md).
This structure MAY include any of the following fields:

- [Algorithm Suite](#algorithm-suite-1)
- [Encryption Context](#encryption-context-2)
- [Plaintext Data Key](#plaintext-data-key-1)

##### Algorithm Suite

The [algorithm suite](algorithm-suites.md) to be used for [decryption](../client-apis/decrypt.md).

##### Encryption Context

The [encryption context](#encryption-context) associated with this [decryption](../client-apis/decrypt.md).

##### Plaintext Data Key

The data key to be used as input for [decryption](../client-apis/decrypt.md).

The plaintext data key MUST:

- Fit the specification for the [encryption algorithm](algorithm-suites.md#encryption-algorithm) included in this decryption material's [algorithm suite](#algorithm-suite-1).
- Consist of cryptographically secure (pseudo-)random bits.
- Be kept secret.

The plaintext data key SHOULD be stored as immutable data.

The plaintext data key SHOULD offer an interface to zero the plaintext data key.

##### Verification Key

The key to be used as the verification key for signature verification during [decryption](../client-apis/decrypt.md).

The verification key MUST fit the specification for the [signature algorithm](algorithm-suites.md#signature-algorithm) included in this decryption material's [algorithm suite](#algorithm-suite-1).
