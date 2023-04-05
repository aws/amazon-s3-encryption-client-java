/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
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
