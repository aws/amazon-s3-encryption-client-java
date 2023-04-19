// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * This interface allows use of key pairs where only one of the public or private keys
 * has been provided. This allows consumers to be able to e.g. provide only the
 * public portion of a key pair in the part of their application which puts encrypted
 * objects into S3 to avoid distributing the private key.
 */
public interface PartialKeyPair {
    PublicKey getPublicKey();

    PrivateKey getPrivateKey();
}
