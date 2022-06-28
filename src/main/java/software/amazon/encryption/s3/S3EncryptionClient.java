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
import software.amazon.encryption.s3.internal.MetadataKey;
import software.amazon.encryption.s3.internal.PutEncryptedObjectPipeline;
import software.amazon.encryption.s3.materials.DecryptMaterialsRequest;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.MaterialsManager;

public class S3EncryptionClient implements S3Client {

    private final S3Client _wrappedClient;
    private final MaterialsManager _materialsManager;

    public S3EncryptionClient(S3Client client, MaterialsManager materialsManager) {
        _wrappedClient = client;
        _materialsManager = materialsManager;
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

        // TODO: This is proof-of-concept code and needs to be refactored

        ResponseInputStream<GetObjectResponse> objectStream = _wrappedClient.getObject(
                getObjectRequest);
        byte[] output;
        try {
            output = IoUtils.toByteArray(objectStream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        GetObjectResponse response = objectStream.response();
        Map<String, String> metadata = response.metadata();

        // Build encrypted data key
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] edkCiphertext = decoder.decode(metadata.get(MetadataKey.ENCRYPTED_DATA_KEY));
        String keyProviderId = metadata.get(MetadataKey.ENCRYPTED_DATA_KEY_ALGORITHM);
        EncryptedDataKey edk = EncryptedDataKey.builder()
                .ciphertext(edkCiphertext)
                .keyProviderId(keyProviderId)
                .build();
        List<EncryptedDataKey> encryptedDataKeys = Collections.singletonList(edk);

        // Get encryption context
        final Map<String, String> encryptionContext = new HashMap<>();
        final String jsonEncryptionContext = metadata.get(MetadataKey.ENCRYPTED_DATA_KEY_CONTEXT);
        try {
            JsonNodeParser parser = JsonNodeParser.create();
            JsonNode objectNode = parser.parse(jsonEncryptionContext);

            for (Map.Entry<String, JsonNode> entry : objectNode.asObject().entrySet()) {
                encryptionContext.put(entry.getKey(), entry.getValue().asString());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Get decryption materials
        final String contentEncryptionAlgorithm = metadata.get(MetadataKey.CONTENT_CIPHER);
        AlgorithmSuite algorithmSuite = null;
        if (contentEncryptionAlgorithm.equals("AES/GCM/NoPadding")) {
            algorithmSuite = AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
        }

        if (algorithmSuite == null) {
            throw new RuntimeException(
                    "Unknown content encryption algorithm: " + contentEncryptionAlgorithm);
        }

        DecryptMaterialsRequest request = DecryptMaterialsRequest.builder()
                .algorithmSuite(algorithmSuite)
                .encryptedDataKeys(encryptedDataKeys)
                .encryptionContext(encryptionContext)
                .build();
        DecryptionMaterials materials = _materialsManager.decryptMaterials(request);

        // Get content encryption information
        SecretKey contentKey = new SecretKeySpec(materials.plaintextDataKey(), "AES");
        final int tagLength = Integer.parseInt(metadata.get(MetadataKey.CONTENT_CIPHER_TAG_LENGTH));
        byte[] iv = decoder.decode(metadata.get(MetadataKey.CONTENT_NONCE));
        final Cipher cipher;
        byte[] plaintext;
        try {
            cipher = Cipher.getInstance(contentEncryptionAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, contentKey, new GCMParameterSpec(tagLength, iv));
            plaintext = cipher.doFinal(output);
        } catch (NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | InvalidAlgorithmParameterException
                 | InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

        try {
            return responseTransformer.transform(response,
                    AbortableInputStream.create(new ByteArrayInputStream(plaintext)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String serviceName() {
        return _wrappedClient.serviceName();
    }

    @Override
    public void close() {
        _wrappedClient.close();
    }
}
