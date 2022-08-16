package software.amazon.encryption.s3.internal;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.legacy.internal.AesCbcContentStrategy;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DecryptMaterialsRequest;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptedDataKey;

public class GetEncryptedObjectPipeline {

    final private S3Client _s3Client;
    final private CryptographicMaterialsManager _cryptoMaterialsManager;

    public static Builder builder() { return new Builder(); }

    private GetEncryptedObjectPipeline(Builder builder) {
        this._s3Client = builder._s3Client;
        this._cryptoMaterialsManager = builder._cryptoMaterialsManager;
    }

    public <T> T getObject(GetObjectRequest getObjectRequest,
            ResponseTransformer<GetObjectResponse, T> responseTransformer) {
        ResponseInputStream<GetObjectResponse> objectStream = _s3Client.getObject(
                getObjectRequest);
        byte[] ciphertext;
        try {
            ciphertext = IoUtils.toByteArray(objectStream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        GetObjectResponse response = objectStream.response();

        // TODO: Need to differentiate metadata decoding strategy here
        ContentMetadataDecodingStrategy contentMetadataDecodingStrategy = S3ObjectMetadataStrategy
                .builder()
                .build();

        Map metadata = response.metadata();

        // If Metadata is not in S3 Object,
        // Pulls metadata from Instruction File which is stored parallel to S3 Object
        if ((metadata == null) || (metadata.get(MetadataKeyConstants.CONTENT_CIPHER) == null)) {
            contentMetadataDecodingStrategy = InstructionFileMetadataDecodingStrategy.builder().build();
            String instructionSuffix = ".instruction";

            GetObjectRequest instructionGetObjectRequest = GetObjectRequest.builder()
                    .bucket(getObjectRequest.bucket())
                    .key(getObjectRequest.key() + instructionSuffix )
                    .build();
            ResponseInputStream<GetObjectResponse> instruction = _s3Client.getObject(instructionGetObjectRequest);

            Map<String, String> metadataContext = new HashMap<>();
            JsonNodeParser parser = JsonNodeParser.create();
            JsonNode objectNode = parser.parse(instruction);
            for (Map.Entry<String, JsonNode> entry : objectNode.asObject().entrySet()) {
                metadataContext.put(entry.getKey(), entry.getValue().asString());
            }
            metadata = metadataContext;
        }

        ContentMetadata contentMetadata = contentMetadataDecodingStrategy.decodeMetadata(metadata);

        AlgorithmSuite algorithmSuite = contentMetadata.algorithmSuite();
        List<EncryptedDataKey> encryptedDataKeys = Collections.singletonList(contentMetadata.encryptedDataKey());

        DecryptMaterialsRequest request = DecryptMaterialsRequest.builder()
                .algorithmSuite(algorithmSuite)
                .encryptedDataKeys(encryptedDataKeys)
                .encryptionContext(contentMetadata.encryptedDataKeyContext())
                .build();

        DecryptionMaterials materials = _cryptoMaterialsManager.decryptMaterials(request);

        ContentDecryptionStrategy contentDecryptionStrategy = null;
        switch (algorithmSuite) {
            case ALG_AES_256_CBC_IV16_NO_KDF:
                contentDecryptionStrategy = AesCbcContentStrategy.builder().build();
                break;
            case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
                contentDecryptionStrategy = AesGcmContentStrategy.builder().build();
                break;
        }
        byte[] plaintext = contentDecryptionStrategy.decryptContent(contentMetadata, materials, ciphertext);

        try {
            return responseTransformer.transform(response,
                    AbortableInputStream.create(new ByteArrayInputStream(plaintext)));
        } catch (Exception e) {
            throw new S3EncryptionClientException("Unable to transform response.", e);
        }
    }

    public static class Builder {
        private S3Client _s3Client;
        private CryptographicMaterialsManager _cryptoMaterialsManager;

        private Builder() {}

        public Builder s3Client(S3Client s3Client) {
            this._s3Client = s3Client;
            return this;
        }

        public Builder cryptoMaterialsManager(CryptographicMaterialsManager cryptoMaterialsManager) {
            this._cryptoMaterialsManager = cryptoMaterialsManager;
            return this;
        }

        public GetEncryptedObjectPipeline build() {
            return new GetEncryptedObjectPipeline(this);
        }
    }
}
