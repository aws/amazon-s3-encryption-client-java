package software.amazon.encryption.s3;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter;
import software.amazon.awssdk.protocols.jsoncore.JsonWriter.JsonGenerationException;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.materials.DefaultMaterialsManager;
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
    public String serviceName() {
        return _wrappedClient.serviceName();
    }

    @Override
    public void close() {
        _wrappedClient.close();
    }
}
