package software.amazon.encryption.s3;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter.JsonGenerationException;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.InvalidObjectStateException;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.DefaultMaterialsManager;
import software.amazon.encryption.s3.materials.DefaultMaterialsManager.DecryptionMaterialsRequest;
import software.amazon.encryption.s3.materials.DefaultMaterialsManager.EncryptionMaterialsRequest;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

public class S3EncryptionClient implements S3Client {

    private final S3Client _wrappedClient;
    private final DefaultMaterialsManager _materialsManager;

    public S3EncryptionClient(S3Client client, DefaultMaterialsManager materialsManager) {
        _wrappedClient = client;
        _materialsManager = materialsManager;
    }

    @Override
    public PutObjectResponse putObject(PutObjectRequest putObjectRequest, RequestBody requestBody)
            throws AwsServiceException, SdkClientException, S3Exception {

        // Get content encryption key
        EncryptionMaterials materials = _materialsManager.getEncryptionMaterials(new EncryptionMaterialsRequest());
        SecretKey contentKey = materials.dataKey();
        // Encrypt content
        byte[] iv = new byte[12]; // default GCM IV length
        new SecureRandom().nextBytes(iv);

        final String contentEncryptionAlgorithm = "AES/GCM/NoPadding";
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(contentEncryptionAlgorithm);
            //GCMParameterSpec defaultSpec = cipher.getParameters().getParameterSpec(GCMParameterSpec.class);
            cipher.init(Cipher.ENCRYPT_MODE, contentKey, new GCMParameterSpec(128, iv));
        } catch (NoSuchAlgorithmException
                 | NoSuchPaddingException
                 | InvalidAlgorithmParameterException
                 | InvalidKeyException e) {
            throw new RuntimeException(e);
        }/* catch (InvalidParameterSpecException e) {
            throw new RuntimeException(e);
        }*/

        byte[] ciphertext;
        try {
            byte[] input = IoUtils.toByteArray(requestBody.contentStreamProvider().newStream());
            ciphertext = cipher.doFinal(input);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

        // Save content metadata into request
        Base64.Encoder encoder = Base64.getEncoder();
        Map<String,String> metadata = new HashMap<>(putObjectRequest.metadata());
        EncryptedDataKey edk = materials.encryptedDataKeys().get(0);
        metadata.put("x-amz-key-v2", encoder.encodeToString(edk.ciphertext()));
        metadata.put("x-amz-iv", encoder.encodeToString(iv));
        metadata.put("x-amz-matdesc", /* TODO: JSON encoded */ "{}");
        metadata.put("x-amz-cek-alg", contentEncryptionAlgorithm);
        metadata.put("x-amz-tag-len", /* TODO: take from algo suite */ "128");
        metadata.put("x-amz-wrap-alg", edk.keyProviderId());

        try (JsonWriter jsonWriter = JsonWriter.create()) {
            jsonWriter.writeStartObject();
            for (Entry<String,String> entry : materials.encryptionContext().entrySet()) {
                jsonWriter.writeFieldName(entry.getKey()).writeValue(entry.getValue());
            }
            jsonWriter.writeEndObject();

            String jsonEncryptionContext = new String(jsonWriter.getBytes(), StandardCharsets.UTF_8);
            metadata.put("x-amz-matdesc", jsonEncryptionContext);
        } catch (JsonGenerationException e) {
            throw new RuntimeException(e);
        }

        putObjectRequest = putObjectRequest.toBuilder().metadata(metadata).build();

        return _wrappedClient.putObject(putObjectRequest, RequestBody.fromBytes(ciphertext));
    }

    @Override
    public <T> T getObject(GetObjectRequest getObjectRequest, ResponseTransformer<GetObjectResponse, T> responseTransformer)
            throws NoSuchKeyException, InvalidObjectStateException, AwsServiceException, SdkClientException, S3Exception {
        ResponseInputStream<GetObjectResponse> objectStream =  _wrappedClient.getObject(getObjectRequest);
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
        byte[] edkCiphertext = decoder.decode(metadata.get("x-amz-key-v2"));
        String keyProviderId = metadata.get("x-amz-wrap-alg");
        EncryptedDataKey edk = EncryptedDataKey.builder()
                .ciphertext(edkCiphertext)
                .keyProviderId(keyProviderId)
                .build();
        List<EncryptedDataKey> encryptedDataKeys = Collections.singletonList(edk);

        // Get encryption context
        final Map<String, String> encryptionContext = new HashMap<>();
        final String jsonEncryptionContext = metadata.get("x-amz-matdesc");
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
        final String contentEncryptionAlgorithm = metadata.get("x-amz-cek-alg");
        int algorithmSuiteId = 0;
        if (contentEncryptionAlgorithm.equals("AES/GCM/NoPadding")) {
            algorithmSuiteId = 0x0078;
        }

        DecryptionMaterialsRequest request = new DecryptionMaterialsRequest();
        request.encryptionContext = encryptionContext;
        request.algorithmSuiteId = algorithmSuiteId;
        request.encryptedDataKeys = encryptedDataKeys;
        DecryptionMaterials materials = _materialsManager.getDecryptionMaterials(request);

        // Get content encryption information
        SecretKey contentKey = new SecretKeySpec(materials.plaintextDataKey(), "AES");
        final int tagLength = Integer.parseInt(metadata.get("x-amz-tag-len"));
        byte[] iv = decoder.decode(metadata.get("x-amz-iv"));
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

//        return _wrappedClient.getObject(getObjectRequest, responseTransformer);
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
