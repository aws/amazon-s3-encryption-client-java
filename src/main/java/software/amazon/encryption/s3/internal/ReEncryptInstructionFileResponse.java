// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

/**
 * Response object returned after re-encrypting an instruction file in S3.
 * Contains the S3 bucket name, object key, and instruction file suffix used for the re-encrypted instruction file
 */
public class ReEncryptInstructionFileResponse {
  private final String bucket;
  private final String key;
  private final String instructionFileSuffix;

  /**
   * Creates a new ReEncryptInstructionFileResponse object with the specified parameters.
   *
   * @param bucket the S3 bucket containing the re-encrypted instruction file
   * @param key the S3 object key of the encrypted object in S3
   * @param instructionFileSuffix the suffix used for the instruction file
   */
  public ReEncryptInstructionFileResponse(String bucket, String key, String instructionFileSuffix) {
    this.bucket = bucket;
    this.key = key;
    this.instructionFileSuffix = instructionFileSuffix.substring(1);
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
   * @return the instruction file suffix used for the instruction file
   */
  public String instructionFileSuffix() {
    return instructionFileSuffix;
  }
}

