package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.services.s3.model.ChecksumType;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import java.time.Instant;
import java.util.Map;

public class ConvertSDKRequests {

  public static CreateMultipartUploadRequest convert(PutObjectRequest request) {

    final CreateMultipartUploadRequest.Builder output = CreateMultipartUploadRequest.builder();
    request
      .toBuilder()
      .sdkFields()
      .forEach(f -> {
        final Object value = f.getValueOrDefault(request);
        if (value != null) {
          switch (f.memberName()) {
            case "ACL":
              output.acl((String) value);
              break;
            case "Bucket":
              output.bucket((String) value);
              break;
            case "BucketKeyEnabled":
              output.bucketKeyEnabled((Boolean) value);
              break;
            case "CacheControl":
              output.cacheControl((String) value);
              break;
            case "ChecksumAlgorithm":
              output.checksumAlgorithm((String) value);
              break;
            case "ChecksumType":
              output.checksumType((ChecksumType) value);
            case "ContentDisposition":
              assert value instanceof String;
              output.contentDisposition((String) value);
              break;
            case "ContentEncoding":
              output.contentEncoding((String) value);
              break;
            case "ContentLanguage":
              output.contentLanguage((String) value);
              break;
            case "ContentType":
              output.contentType((String) value);
              break;
            case "ExpectedBucketOwner":
              output.expectedBucketOwner((String) value);
              break;
            case "Expires":
              output.expires((Instant) value);
              break;
            case "GrantFullControl":
              output.grantFullControl((String) value);
              break;
            case "GrantRead":
              output.grantRead((String) value);
              break;
            case "GrantReadACP":
              output.grantReadACP((String) value);
              break;
            case "GrantWriteACP":
              output.grantWriteACP((String) value);
              break;
            case "Key":
              output.key((String) value);
              break;
            case "Metadata":
              // The PutObjectRequest.builder().metadata(value)
              // only takes Map<String, String> therefore it should not be possible
              // to get here with anything other than a Map<String, String>
              // This may be overkill, but this map should be small
              // so the performance hit to verify this is worth the correctness.
              if (!isStringStringMap(value)) {
                throw new IllegalArgumentException("Metadata must be a Map<String, String>");
              }
              @SuppressWarnings("unchecked")
              Map<String, String> metadata = (Map<String, String>) value;
              output.metadata(metadata);
              break;
            case "ObjectLockLegalHoldStatus":
              output.objectLockLegalHoldStatus((String) value);
              break;
            case "ObjectLockMode":
              output.objectLockMode((String) value);
              break;
            case "ObjectLockRetainUntilDate":
              output.objectLockRetainUntilDate((Instant) value);
              break;
            case "RequestPayer":
              output.requestPayer((String) value);
              break;
            case "ServerSideEncryption":
              output.serverSideEncryption((String) value);
              break;
            case "SSECustomerAlgorithm":
              output.sseCustomerAlgorithm((String) value);
              break;
            case "SSECustomerKey":
              output.sseCustomerKey((String) value);
              break;
            case "SSEKMSEncryptionContext":
              output.ssekmsEncryptionContext((String) value);
              break;
            case "SSEKMSKeyId":
              output.ssekmsKeyId((String) value);
              break;
            case "StorageClass":
              output.storageClass((String) value);
              break;
            case "Tagging":
              output.tagging((String) value);
              break;
            case "WebsiteRedirectLocation":
              output.websiteRedirectLocation((String) value);
              break;
            default:
              // Rather than silently dropping the value,
              // we loudly signal that we don't know how to handle this field.
              throw new IllegalArgumentException(
                f.locationName() + " is an unknown field. " +
                  "The S3Encryption Client will not silently disable this option." +
                  "This may be a new S3 feature." +
                  "Please report this to the Amazon S3 Encryption Client for Java: " +
                  "https://github.com/aws/amazon-s3-encryption-client-java/issues." +
                  "To work around this issue you can disable multi part upload," +
                  "or not set this value on put." +
                  "You may also be able to update this value after the pub object request completes."
              );
          }
        }
      });
    return output
      // OverrideConfiguration is not as SDKField but still needs to be supported
      .overrideConfiguration(request.overrideConfiguration().orElse(null))
      .build();
  }

  private static boolean isStringStringMap(Object value) {
    if (!(value instanceof Map)) {
      return false;
    }
    Map<?, ?> map = (Map<?, ?>) value;
    return map.entrySet().stream()
      .allMatch(entry -> entry != null
        && ((Map.Entry<?, ?>) entry).getKey() instanceof String
        && ((Map.Entry<?, ?>) entry).getValue() instanceof String);
  }
}
