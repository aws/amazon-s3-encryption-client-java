package software.amazon.encryption.s3;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.internal.GetEncryptedObjectPipeline;
import software.amazon.encryption.s3.internal.MetadataKey;
import software.amazon.encryption.s3.internal.PutEncryptedObjectPipeline;
import software.amazon.encryption.s3.materials.DecryptMaterialsRequest;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.MaterialsManager;

public class S3EncryptionClient implements S3Client {

    private final S3Client _wrappedClient;
    private final MaterialsManager _materialsManager;

    private S3EncryptionClient(Builder builder) {
        _wrappedClient = builder._wrappedClient;
        _materialsManager = builder._materialsManager;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public PutObjectResponse putObject(PutObjectRequest putObjectRequest, RequestBody requestBody)
            throws AwsServiceException, SdkClientException {

        PutEncryptedObjectPipeline pipeline = PutEncryptedObjectPipeline.builder()
                .s3Client(_wrappedClient)
                .materialsManager(_materialsManager)
                .build();

        return pipeline.putObject(putObjectRequest, requestBody);
    }

    @Override
    public <T> T getObject(GetObjectRequest getObjectRequest,
            ResponseTransformer<GetObjectResponse, T> responseTransformer)
            throws AwsServiceException, SdkClientException {

        GetEncryptedObjectPipeline pipeline = GetEncryptedObjectPipeline.builder()
                .s3Client(_wrappedClient)
                .cryptoMaterialsManager(_cryptoMaterialsManager)
                .build();

        return pipeline.getObject(getObjectRequest, responseTransformer);
    }

    @Override
    public String serviceName() {
        return _wrappedClient.serviceName();
    }

    @Override
    public void close() {
        _wrappedClient.close();
    }

    public static class Builder {
        private S3Client _wrappedClient = S3Client.builder().build();
        private MaterialsManager _materialsManager;

        private Builder() {}

        public Builder wrappedClient(S3Client wrappedClient) {
            this._wrappedClient = wrappedClient;
            return this;
        }

        public Builder materialsManager(MaterialsManager materialsManager) {
            this._materialsManager = materialsManager;
            return this;
        }

        public S3EncryptionClient build() {
            return new S3EncryptionClient(this);
        }
    }
}
