package software.amazon.encryption.s3.internal;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.services.s3.model.*;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class ConvertSDKRequestsTest {

  @Test
  void testConvertPutObjectRequest_Bucket() {
    final String value = "test-bucket";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .bucket(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.bucket());
  }

  @Test
  void testConvertPutObjectRequest_ACL() {
    final ObjectCannedACL value = ObjectCannedACL.PRIVATE;
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .acl(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.acl());
  }

  @Test
  void testConvertPutObjectRequest_ACL2() {
    final String value = ObjectCannedACL.PRIVATE.toString();
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .acl(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.acl().toString());
  }

  @Test
  void testConvertPutObjectRequest_BucketKeyEnabled() {
    final Boolean value = true;
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .bucketKeyEnabled(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.bucketKeyEnabled());
  }

  @Test
  void testConvertPutObjectRequest_CacheControl() {
    final String value = "max-age=3600";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .cacheControl(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.cacheControl());
  }

  @Test
  void testConvertPutObjectRequest_ChecksumAlgorithm() {
    final ChecksumAlgorithm value = ChecksumAlgorithm.SHA256;
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .checksumAlgorithm(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.checksumAlgorithm());
  }

  @Test
  void testConvertPutObjectRequest_ChecksumAlgorithm2() {
    final String value = ChecksumAlgorithm.SHA256.toString();
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .checksumAlgorithm(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.checksumAlgorithm().toString());
  }

  @Test
  void testConvertPutObjectRequest_ContentDisposition() {
    final String value = "attachment; filename=\"filename.jpg\"";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .contentDisposition(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.contentDisposition());
  }

  @Test
  void testConvertPutObjectRequest_ContentEncoding() {
    final String value = "gzip";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .contentEncoding(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.contentEncoding());
  }

  @Test
  void testConvertPutObjectRequest_ContentLanguage() {
    final String value = "en-US";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .contentLanguage(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.contentLanguage());
  }

  @Test
  void testConvertPutObjectRequest_ContentType() {
    final String value = "text/plain";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .contentType(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.contentType());
  }

  @Test
  void testConvertPutObjectRequest_ExpectedBucketOwner() {
    final String value = "owner123";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .expectedBucketOwner(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.expectedBucketOwner());
  }

  @Test
  void testConvertPutObjectRequest_Expires() {
    final Instant value = Instant.now();
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .expires(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.expires());
  }

  @Test
  void testConvertPutObjectRequest_GrantFullControl() {
    final String value = "id=123";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .grantFullControl(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.grantFullControl());
  }

  @Test
  void testConvertPutObjectRequest_GrantRead() {
    final String value = "id=123";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .grantRead(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.grantRead());
  }

  @Test
  void testConvertPutObjectRequest_GrantReadACP() {
    final String value = "id=123";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .grantReadACP(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.grantReadACP());
  }

  @Test
  void testConvertPutObjectRequest_GrantWriteACP() {
    final String value = "id=123";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .grantWriteACP(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.grantWriteACP());
  }

  @Test
  void testConvertPutObjectRequest_Key() {
    final String value = "test-key";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .key(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.key());
  }

  @Test
  void testConvertPutObjectRequest_Metadata() {
    final Map<String, String> value = new HashMap<>();
    value.put("key1", "value1");
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .metadata(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.metadata());
  }

  @Test
  void testConvertPutObjectRequest_ObjectLockLegalHoldStatus() {
    final ObjectLockLegalHoldStatus value = ObjectLockLegalHoldStatus.ON;
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .objectLockLegalHoldStatus(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.objectLockLegalHoldStatus());
  }

  @Test
  void testConvertPutObjectRequest_ObjectLockLegalHoldStatus2() {
    final String value = ObjectLockLegalHoldStatus.ON.toString();
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .objectLockLegalHoldStatus(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.objectLockLegalHoldStatus().toString());
  }

  @Test
  void testConvertPutObjectRequest_ObjectLockMode() {
    final ObjectLockMode value = ObjectLockMode.GOVERNANCE;
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .objectLockMode(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.objectLockMode());
  }

  @Test
  void testConvertPutObjectRequest_ObjectLockMode2() {
    final String value = "GOVERNANCE";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .objectLockMode(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.objectLockMode().toString());
  }

  @Test
  void testConvertPutObjectRequest_ObjectLockRetainUntilDate() {
    final Instant value = Instant.now();
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .objectLockRetainUntilDate(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.objectLockRetainUntilDate());
  }

  @Test
  void testConvertPutObjectRequest_RequestPayer() {
    final RequestPayer value = RequestPayer.REQUESTER;
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .requestPayer(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.requestPayer());
  }

  @Test
  void testConvertPutObjectRequest_RequestPayer2() {
    final String value = RequestPayer.REQUESTER.toString();
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .requestPayer(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.requestPayer().toString());
  }

  @Test
  void testConvertPutObjectRequest_ServerSideEncryption() {
    final ServerSideEncryption value = ServerSideEncryption.AES256;
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .serverSideEncryption(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.serverSideEncryption());
  }

  @Test
  void testConvertPutObjectRequest_ServerSideEncryption2() {
    final String value = ServerSideEncryption.AES256.toString();
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .serverSideEncryption(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.serverSideEncryption().toString());
  }

  @Test
  void testConvertPutObjectRequest_SSECustomerAlgorithm() {
    final String value = "AES256";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .sseCustomerAlgorithm(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.sseCustomerAlgorithm());
  }

  @Test
  void testConvertPutObjectRequest_SSECustomerKey() {
    final String value = "key123";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .sseCustomerKey(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.sseCustomerKey());
  }

  @Test
  void testConvertPutObjectRequest_SSEKMSKeyId() {
    final String value = "arn:aws:kms:region:123456789012:key/key-id";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .ssekmsKeyId(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.ssekmsKeyId());
  }

  @Test
  void testConvertPutObjectRequest_SSEKMSEncryptionContext() {
    final String value = "context123";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .ssekmsEncryptionContext(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.ssekmsEncryptionContext());
  }

  @Test
  void testConvertPutObjectRequest_StorageClass() {
    final StorageClass value = StorageClass.STANDARD;
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .storageClass(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.storageClass());
  }

  @Test
  void testConvertPutObjectRequest_StorageClass2() {
    final String value = StorageClass.STANDARD.toString();
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .storageClass(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.storageClass().toString());
  }

  @Test
  void testConvertPutObjectRequest_Tagging() {
    final String value = "key1=value1&key2=value2";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .tagging(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.tagging());
  }

  @Test
  void testConvertPutObjectRequest_WebsiteRedirectLocation() {
    final String value = "/redirected";
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .websiteRedirectLocation(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertEquals(value, convertedRequest.websiteRedirectLocation());
  }

  @Test
  void testConvertPutObjectRequest_OverrideConfiguration() {
    final AwsRequestOverrideConfiguration value = AwsRequestOverrideConfiguration
      .builder()
      .apiCallAttemptTimeout(Duration.ofMillis(100))
      .build();
    PutObjectRequest originalRequest = PutObjectRequest.builder()
      .overrideConfiguration(value)
      .build();
    final CreateMultipartUploadRequest convertedRequest = ConvertSDKRequests.convert(originalRequest);
    assertNotNull(convertedRequest);
    assertTrue(convertedRequest.overrideConfiguration().isPresent());
    assertEquals(value, convertedRequest.overrideConfiguration().get());
  }
}
