// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.RawKeyring;

import static software.amazon.encryption.s3.S3EncryptionClientUtilities.DEFAULT_INSTRUCTION_FILE_SUFFIX;

/**
 * Request object for re-encrypting instruction files in S3.
 * This request supports re-encryption operations using either AES or RSA keyrings.
 * For AES keyrings, only the default instruction file suffix is supported.
 * For RSA keyrings, both the default and custom instruction file suffixes are supported.
 */
public class ReEncryptInstructionFileRequest {
  private final String bucket;
  private final String key;
  private final RawKeyring newKeyring;
  private final String instructionFileSuffix;

  private ReEncryptInstructionFileRequest(Builder builder) {
    bucket = builder.bucket;
    key = builder.key;
    newKeyring = builder.newKeyring;
    instructionFileSuffix = builder.instructionFileSuffix;
  }

  /**
   * @return the S3 bucket name that contains the encrypted object and instruction file to re-encrypt
   */
  public String bucket() {
    return bucket;
  }

  /**
   * @return the S3 object key of the encrypted object whose instruction file will be re-encrypted
   */
  public String key() {
    return key;
  }

  /**
   * @return the new keyring (AES or RSA) that will be used to re-encrypt the instruction file
   */
  public RawKeyring newKeyring() {
    return newKeyring;
  }

  /**
   * @return the suffix to use for the instruction file. The default instruction file suffix is ".instruction"
   */
  public String instructionFileSuffix() {
    return instructionFileSuffix;
  }

  /**
   * Creates a builder that can be used to configure and create a {@link ReEncryptInstructionFileRequest}
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Builder for ReEncryptInstructionFileRequest.
   */
  public static class Builder {
    private String bucket;
    private String key;
    private RawKeyring newKeyring;
    private String instructionFileSuffix = DEFAULT_INSTRUCTION_FILE_SUFFIX;

    /**
     * Sets the S3 bucket name for the re-encryption of instruction file.
     *
     * @param bucket the S3 bucket name
     * @return a reference to this object so that method calls can be chained together.
     */
    public Builder bucket(String bucket) {
      this.bucket = bucket;
      return this;
    }

    /**
     * Sets the S3 object key for the re-encryption of instruction file.
     *
     * @param key the S3 object key
     * @return a reference to this object so that method calls can be chained together.
     */
    public Builder key(String key) {
      this.key = key;
      return this;
    }

    /**
     * Sets the new keyring for re-encryption of instruction file.
     *
     * @param newKeyring the new keyring for re-encryption
     * @return a reference to this object so that method calls can be chained together.
     */
    public Builder newKeyring(RawKeyring newKeyring) {
      this.newKeyring = newKeyring;
      return this;
    }

    /**
     * Sets a custom instruction file suffix for the re-encrypted instruction file.
     * For AES keyrings, only the default instruction file suffix is allowed.
     * For RSA keyrings, both the default and custom instruction file suffixes are allowed.
     * Note: The "." prefix is automatically added to the suffix
     *
     * @param instructionFileSuffix the instruction file suffix
     * @return a reference to this object so that method calls can be chained together.
     */
    public Builder instructionFileSuffix(String instructionFileSuffix) {
      this.instructionFileSuffix = "." + instructionFileSuffix;
      return this;
    }

    /**
     * Validates and builds the ReEncryptInstructionFileRequest according
     * to the configuration options passed to the Builder object.
     *
     * @return an instance of the ReEncryptInstructionFileRequest
     */
    public ReEncryptInstructionFileRequest build() {
      if (bucket == null || bucket.isEmpty()) {
        throw new S3EncryptionClientException("Bucket must be provided!");
      }
      if (key == null || key.isEmpty()) {
        throw new S3EncryptionClientException("Key must be provided!");
      }
      if (newKeyring == null) {
        throw new S3EncryptionClientException("New keyring must be provided!");
      }
      if (newKeyring instanceof AesKeyring) {
        if (!instructionFileSuffix.equals(DEFAULT_INSTRUCTION_FILE_SUFFIX)) {
          throw new S3EncryptionClientException("Custom Instruction file suffix is not applicable for AES keyring!");
        }
      }
      return new ReEncryptInstructionFileRequest(this);
    }

  }

}
