package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.RawKeyring;
import software.amazon.encryption.s3.materials.RsaKeyring;

/** Request object for re-encrypting instruction files.
 * Supports both AES and RSA keyring with different instruction file suffixes.
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

  public String bucket() {
    return bucket;
  }

  public String key() {
    return key;
  }

  public RawKeyring newKeyring() {
    return newKeyring;
  }

  public String instructionFileSuffix() {
    return instructionFileSuffix;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private static final String DEFAULT_INSTRUCTION_FILE_SUFFIX = ".instruction";
    private String bucket;
    private String key;
    private RawKeyring newKeyring;
    private String instructionFileSuffix = DEFAULT_INSTRUCTION_FILE_SUFFIX;

    public Builder bucket(String bucket) {
      this.bucket = bucket;
      return this;
    }

    public Builder key(String key) {
      this.key = key;
      return this;
    }

    public Builder newKeyring(RawKeyring newKeyring) {
      this.newKeyring = newKeyring;
      return this;
    }

    public Builder instructionFileSuffix(String instructionFileSuffix) {
      this.instructionFileSuffix = "." + instructionFileSuffix;
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
      }
      return new ReEncryptInstructionFileRequest(this);
    }

  }

}
