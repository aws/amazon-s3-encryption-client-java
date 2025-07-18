// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

/**
 * Response object returned after re-encrypting an instruction file in S3.
 * Contains the S3 bucket name, object key, instruction file suffix, and rotation enforcement status for the re-encrypted instruction file
 */
public class ReEncryptInstructionFileResponse {
  private final String bucket;
  private final String key;
  private final String instructionFileSuffix;
  private final boolean enforceRotation;

  /**
   * Creates a new ReEncryptInstructionFileResponse object with the specified parameters.
   *
   * @param bucket the S3 bucket containing the re-encrypted instruction file
   * @param key the S3 object key of the encrypted object in S3
   * @param instructionFileSuffix the suffix used for the instruction file
   * @param enforceRotation whether rotation was enforced for the re-encrypted instruction file
   */
  public ReEncryptInstructionFileResponse(String bucket, String key, String instructionFileSuffix, boolean enforceRotation) {
    this.bucket = bucket;
    this.key = key;
    this.instructionFileSuffix = instructionFileSuffix.substring(1);
    this.enforceRotation = enforceRotation;
  }

  /**
   * @return the S3 bucket containing the re-encrypted instruction file
   */
  public String bucket() {
    return bucket;
  }

  /**
   * @return the S3 object key of the encrypted object in S3
   */
  public String key() {
    return key;
  }

  /**
   * @return whether rotation was enforced for the re-encrypted instruction file
   */
  public boolean enforceRotation() {
    return enforceRotation;
  }

  /**
   * @return the instruction file suffix used for the instruction file
   */
  public String instructionFileSuffix() {
    return instructionFileSuffix;
  }
}

