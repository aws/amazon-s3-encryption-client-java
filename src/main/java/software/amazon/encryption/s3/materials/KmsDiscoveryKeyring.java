package software.amazon.encryption.s3.materials;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.core.ApiName;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.internal.ApiNameVersion;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class KmsDiscoveryKeyring extends S3Keyring {
  private static final ApiName API_NAME = ApiNameVersion.apiNameWithVersion();
  private static final String KEY_ID_CONTEXT_KEY = "kms_cmk_id";

  private final KmsClient _kmsClient;

  public KmsDiscoveryKeyring(Builder builder) {
    super(builder);

    _kmsClient = builder._kmsClient;
    decryptDataKeyStrategies.put(_kmsDiscoveryStrategy.keyProviderInfo(), _kmsDiscoveryStrategy);
    decryptDataKeyStrategies.put(_kmsContextDiscoveryStrategy.keyProviderInfo(), _kmsContextDiscoveryStrategy);
  }

  private final DecryptDataKeyStrategy _kmsDiscoveryStrategy = new DecryptDataKeyStrategy() {

    private static final String KEY_PROVIDER_INFO = "kms";

    @Override
    public boolean isLegacy() {
      return true;
    }

    @Override
    public String keyProviderInfo() {
      return KEY_PROVIDER_INFO;
    }

    @Override
    public byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey) {
      DecryptRequest request = DecryptRequest.builder()
        .encryptionContext(materials.encryptionContext())
        .ciphertextBlob(SdkBytes.fromByteArray(encryptedDataKey))
        .overrideConfiguration(builder -> builder.addApiName(API_NAME))
        .build();

      DecryptResponse response = _kmsClient.decrypt(request);
      return response.plaintext().asByteArray();
    }
  };

  private final DecryptDataKeyStrategy _kmsContextDiscoveryStrategy = new DecryptDataKeyStrategy() {

    private static final String KEY_PROVIDER_INFO = "kms+context";
    private static final String ENCRYPTION_CONTEXT_ALGORITHM_KEY = "aws:x-amz-cek-alg";

    @Override
    public boolean isLegacy() {
      return false;
    }

    @Override
    public String keyProviderInfo() {
      return KEY_PROVIDER_INFO;
    }

    @Override
    public byte[] decryptDataKey(DecryptionMaterials materials, byte[] encryptedDataKey) {
      Map<String, String> requestEncryptionContext = new HashMap<>();
      GetObjectRequest s3Request = materials.s3Request();
      if (s3Request.overrideConfiguration().isPresent()) {
        AwsRequestOverrideConfiguration overrideConfig = s3Request.overrideConfiguration().get();
        Optional<Map<String, String>> optEncryptionContext = overrideConfig
          .executionAttributes()
          .getOptionalAttribute(S3EncryptionClient.ENCRYPTION_CONTEXT);
        if (optEncryptionContext.isPresent()) {
          requestEncryptionContext = new HashMap<>(optEncryptionContext.get());
        }
      }

      // We are validating the encryption context to match S3EC V2 behavior
      Map<String, String> materialsEncryptionContextCopy = new HashMap<>(materials.encryptionContext());
      materialsEncryptionContextCopy.remove(KEY_ID_CONTEXT_KEY);
      materialsEncryptionContextCopy.remove(ENCRYPTION_CONTEXT_ALGORITHM_KEY);
      if (!materialsEncryptionContextCopy.equals(requestEncryptionContext)) {
        throw new S3EncryptionClientException("Provided encryption context does not match information retrieved from S3");
      }

      DecryptRequest request = DecryptRequest.builder()
        .encryptionContext(materials.encryptionContext())
        .ciphertextBlob(SdkBytes.fromByteArray(encryptedDataKey))
        .overrideConfiguration(builder -> builder.addApiName(API_NAME))
        .build();

      DecryptResponse response = _kmsClient.decrypt(request);
      return response.plaintext().asByteArray();
    }
  };

  private final Map<String, DecryptDataKeyStrategy> decryptDataKeyStrategies = new HashMap<>();

  public static Builder builder() {
    return new Builder();
  }

  @Override
  protected GenerateDataKeyStrategy generateDataKeyStrategy() {
    throw new S3EncryptionClientException("KmsDiscoveryKeyring does not support GenerateDataKey");
  }

  @Override
  protected EncryptDataKeyStrategy encryptDataKeyStrategy() {
    throw new S3EncryptionClientException("KmsDiscoveryKeyring does not support EncryptDataKey");
  }

  @Override
  protected Map<String, DecryptDataKeyStrategy> decryptDataKeyStrategies() {
    return decryptDataKeyStrategies;
  }

  public static class Builder extends S3Keyring.Builder<KmsDiscoveryKeyring, Builder> {
    private KmsClient _kmsClient;
    private String _wrappingKeyId;

    private Builder() {
      super();
    }

    @Override
    protected Builder builder() {
      return this;
    }

    /**
     * Note that this does NOT create a defensive clone of KmsClient. Any modifications made to the wrapped
     * client will be reflected in this Builder.
     */
    @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "Pass mutability into wrapping client")
    public Builder kmsClient(KmsClient kmsClient) {
      _kmsClient = kmsClient;
      return this;
    }

    public KmsDiscoveryKeyring build() {
      if (_kmsClient == null) {
        _kmsClient = KmsClient.create();
      }

      return new KmsDiscoveryKeyring(this);
    }
  }
}
