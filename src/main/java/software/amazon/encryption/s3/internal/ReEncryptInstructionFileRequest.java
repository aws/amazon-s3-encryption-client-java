package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.KmsKeyring;
import software.amazon.encryption.s3.materials.RsaKeyring;
import software.amazon.encryption.s3.materials.S3Keyring;

/** Request object for re-encrypting instruction files.
 * Supports both AES and RSA keyring with different instruction file suffixes.
 */
public class ReEncryptInstructionFileRequest {
  private final String bucket;
  private final String key;
  private final S3Keyring newKeyring;
  private final String instructionFileSuffix;

  private ReEncryptInstructionFileRequest(Builder builder) {
    bucket = builder.bucket;
    key = builder.key;
    newKeyring = builder.newKeyring;
    instructionFileSuffix = builder.instructionFileSuffix;
  }
  public static Builder builder() {
    return new Builder();
  }
  public static class Builder {
    private static final String DEFAULT_INSTRUCTION_FILE_SUFFIX = ".instruction";
    private String bucket;
    private String key;
    private S3Keyring newKeyring;
    private String instructionFileSuffix = DEFAULT_INSTRUCTION_FILE_SUFFIX;

    public Builder bucket(String bucket) {
      this.bucket = bucket;
      return this;
    }

    public Builder key(String key) {
      this.key = key;
      return this;
    }

    public Builder newKeyring(S3Keyring newKeyring) {
      this.newKeyring = newKeyring;
      return this;
    }

    public Builder instructionFileSuffix(String instructionFileSuffix) {
      this.instructionFileSuffix = instructionFileSuffix;
      return this;
    }

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
          throw new S3EncryptionClientException("Instruction file suffix is not applicable for AES keyring!");
        }
      } else if (newKeyring instanceof RsaKeyring) {
        if (instructionFileSuffix.equals(DEFAULT_INSTRUCTION_FILE_SUFFIX)) {
          throw new S3EncryptionClientException("Instruction file suffix must be different than the default one for RSA keyring!");
        }
      } else if (newKeyring instanceof KmsKeyring){
        throw new S3EncryptionClientException("KMS keyring is not supported for re-encrypting instruction file!");
      }
      return new ReEncryptInstructionFileRequest(this);
    }

  }

}
