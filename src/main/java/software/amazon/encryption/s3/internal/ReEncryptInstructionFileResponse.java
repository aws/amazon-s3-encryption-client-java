package software.amazon.encryption.s3.internal;

/** Response object for re-encrypting instruction files.
 * Contains the bucket, key, and instruction file suffix of the re-encrypted instruction file in S3.
 */

public class ReEncryptInstructionFileResponse {
  private final String bucket;
  private final String key;
  private final String instructionFileSuffix;

  public ReEncryptInstructionFileResponse(String bucket, String key, String instructionFileSuffix) {
    this.bucket = bucket;
    this.key = key;
    this.instructionFileSuffix = instructionFileSuffix;
  }
  public String Bucket() {
    return bucket;
  }
  public String Key() {
    return key;
  }
  public String InstructionFileSuffix() {
    return instructionFileSuffix;
  }
}

