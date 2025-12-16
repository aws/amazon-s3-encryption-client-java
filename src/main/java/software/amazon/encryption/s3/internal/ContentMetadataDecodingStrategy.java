// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import com.sun.xml.messaging.saaj.packaging.mime.internet.MimeUtility;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.protocols.jsoncore.JsonNode;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.encryption.s3.S3EncryptionClient;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.S3EncryptionClientSecurityException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.EncryptedDataKey;
import software.amazon.encryption.s3.materials.MaterialsDescription;
import software.amazon.encryption.s3.materials.S3Keyring;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletionException;

import static software.amazon.encryption.s3.S3EncryptionClientUtilities.DEFAULT_INSTRUCTION_FILE_SUFFIX;

public class ContentMetadataDecodingStrategy {

    private static final Base64.Decoder DECODER = Base64.getDecoder();

    private final InstructionFileConfig instructionFileConfig_;

    public ContentMetadataDecodingStrategy(InstructionFileConfig instructionFileConfig) {
        if (instructionFileConfig == null) {
            throw new S3EncryptionClientException("ContentMetadataDecodingStrategy requires a non-null instruction file config.");
        }
        instructionFileConfig_ = instructionFileConfig;
    }

    // S3EC Java supports decoding the S3 Server's "double encoding".
    //= specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
    //= type=exception
    //# If the S3EC does not support decoding the S3 Server's "double encoding" then it MUST return the content metadata untouched.
    //= specification/s3-encryption/data-format/metadata-strategy.md#object-metadata
    //# The S3EC SHOULD support decoding the S3 Server's "double encoding".
    private static String decodeS3CustomEncoding(final String s) {
        final String mimeDecoded;
        try {
            mimeDecoded = MimeUtility.decodeText(s);
        } catch (UnsupportedEncodingException ex) {
            throw new S3EncryptionClientException("Unable to decode S3 object metadata: " + s, ex);
        }
        // Once MIME decoded, we need to recover the correct code points from the second encoding pass
        // Otherwise, decryption fails
        try {
            final StringBuilder stringBuilder = new StringBuilder();
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final DataOutputStream out = new DataOutputStream(baos);
            final byte[] sInBytes = mimeDecoded.getBytes(StandardCharsets.UTF_8);
            final char[] sInChars = mimeDecoded.toCharArray();

            int nonAsciiChars = 0;
            for (int i = 0; i < sInChars.length; i++) {
                if (sInChars[i] > 127) {
                    byte[] buf = {sInBytes[i + nonAsciiChars], sInBytes[i + nonAsciiChars + 1]};
                    // temporarily re-encode as UTF-8
                    String wrongString = new String(buf, StandardCharsets.UTF_8);
                    // write its code point
                    out.write(wrongString.charAt(0));
                    nonAsciiChars++;
                } else {
                    if (baos.size() > 0) {
                        // This is not the most efficient, but we prefer to specify UTF_8
                        stringBuilder.append(new String(baos.toByteArray(), StandardCharsets.UTF_8));
                        baos.reset();
                    }
                    stringBuilder.append(sInChars[i]);
                }
            }
            return stringBuilder.toString();
        } catch (IOException exception) {
            throw new S3EncryptionClientException("Unable to decode S3 object metadata: " + s, exception);
        }
    }

    private static ContentMetadata readFromV3FormatMap(Map<String, String> metadata, GetObjectResponse response) {
        if (!MetadataKeyConstants.isV3Format(metadata)) {
            //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //# In general, if there is any deviation from the above format, with the exception of additional unrelated mapkeys, then the S3EC SHOULD throw an exception.
            throw new S3EncryptionClientException("Content metadata is tampered, required metadata to decrypt the object are missing");
        }

        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //# - The mapkey "x-amz-c" MUST be present for V3 format objects.
        final String contentEncryptionAlgorithm = metadata.get(MetadataKeyConstants.CONTENT_CIPHER_V3);
        AlgorithmSuite algorithmSuite;
        String contentRange = response.contentRange();
        // This is the only alg suite supported by the V3 format
        //= specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
        //# Objects encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY MUST use the V3 message format version only.
        if (contentEncryptionAlgorithm.equals(AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY.idAsString())) {
            //= specification/s3-encryption/decryption.md#ranged-gets
            //# If the object was encrypted with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, then
            //# ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY MUST be used to decrypt the range of the object.
            algorithmSuite = (contentRange == null)
                    ? AlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
                    : AlgorithmSuite.ALG_AES_256_CTR_HKDF_SHA512_COMMIT_KEY;
        } else {
            throw new S3EncryptionClientException(
                    "Unknown content encryption algorithm for V3 message format: " + contentEncryptionAlgorithm);
        }

        // Currently, this is not stored within the metadata,
        // signal to keyring(s) intended for S3EC
        final String keyProviderId = S3Keyring.KEY_PROVIDER_ID;
        // These are standardized and constrained to valid values in v3
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //# - The mapkey "x-amz-3" MUST be present for V3 format objects.
        byte[] edkCiphertext = DECODER.decode(metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V3));
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //# - The mapkey "x-amz-w" MUST be present for V3 format objects.
        String keyProviderInfo = MetadataKeyConstants.decompressWrappingAlgorithm(metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM_V3));

        // Build encrypted data key
        EncryptedDataKey edk = EncryptedDataKey.builder()
                .encryptedDataKey(edkCiphertext)
                .keyProviderId(keyProviderId)
                .keyProviderInfo(keyProviderInfo)
                .build();

        Map<String, String> encryptionContext;
        MaterialsDescription materialsDescription;
        if (keyProviderInfo.equals(MetadataKeyConstants.V3_ALG_KMS_CONTEXT)) {
            //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-t" SHOULD be present for V3 format objects that use KMS Encryption Context.
            //= specification/s3-encryption/data-format/content-metadata.md#v3-only
            //# The Encryption Context value MUST be used for wrapping algorithm `kms+context` or `12`.
            //= specification/s3-encryption/data-format/content-metadata.md#v3-only
            //# If the mapkey x-amz-t is not present, the default Material Description value MUST be set to an empty map (`{}`).
            String jsonString = metadata.getOrDefault(MetadataKeyConstants.ENCRYPTION_CONTEXT_V3, "{}");
            //= specification/s3-encryption/data-format/content-metadata.md#v3-only
            //= type=implication
            //# This encryption context string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
            encryptionContext = decodeAndParseJsonString(jsonString);
            materialsDescription = MaterialsDescription.builder().build();
        } else {
            //= specification/s3-encryption/data-format/content-metadata.md#v3-only
            //# The Material Description MUST be used for wrapping algorithms `AES/GCM` (`02`) and `RSA-OAEP-SHA1` (`22`).
            //= specification/s3-encryption/data-format/content-metadata.md#v3-only
            //# If the mapkey x-amz-m is not present, the default Material Description value MUST be set to an empty map (`{}`).
            //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# - The mapkey "x-amz-m" SHOULD be present for V3 format objects that use Raw Keyring Material Description.
            String jsonString = metadata.getOrDefault(MetadataKeyConstants.MAT_DESC_V3, "{}");
            //= specification/s3-encryption/data-format/content-metadata.md#v3-only
            //= type=implication
            //# This material description string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
            materialsDescription = MaterialsDescription.builder()
                    .putAll(decodeAndParseJsonString(jsonString))
                    .build();
            encryptionContext = new HashMap<>();
        }

        // Get content iv - in v3, the GCM IV is zeros,
        // but the MessageId functions as a nonce.
        // We can just reuse the iv field in materials.
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //# - The mapkey "x-amz-i" MUST be present for V3 format objects.
        byte[] messageId = DECODER.decode(metadata.get(MetadataKeyConstants.MESSAGE_ID_V3));

        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //# - The mapkey "x-amz-d" MUST be present for V3 format objects.
        byte[] keyCommitment = DECODER.decode(metadata.get(MetadataKeyConstants.KEY_COMMITMENT_V3));

        return ContentMetadata.builder()
                .algorithmSuite(algorithmSuite)
                .encryptedDataKey(edk)
                .encryptionContext(encryptionContext)
                .materialsDescription(materialsDescription)
                .contentMessageId(messageId)
                .contentRange(contentRange)
                .keyCommitment(keyCommitment)
                .build();
    }

    /*
     * Decodes and parses a String -> String map encoded as Json,
     * and possibly encoded with S3 server's weird encoding.
     * Shared by v1/v2 MatDesc and v3 MatDesc and EncCtx maps.
     */
    private static Map<String, String> decodeAndParseJsonString(String jsonEncryptionContext) {
        final Map<String, String> jsonMap = new HashMap<>();
        // When the encryption context or mat desc contains non-US-ASCII characters,
        // the S3 server applies an esoteric encoding to the object metadata.
        // Reverse that, to allow decryption.
        final String decodedJsonEncryptionContext = decodeS3CustomEncoding(jsonEncryptionContext);
        try {
            JsonNodeParser parser = JsonNodeParser.create();
            JsonNode objectNode = parser.parse(decodedJsonEncryptionContext);

            for (Map.Entry<String, JsonNode> entry : objectNode.asObject().entrySet()) {
                jsonMap.put(entry.getKey(), entry.getValue().asString());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return jsonMap;
    }

    private static ContentMetadata readFromMapV1V2(Map<String, String> metadata, GetObjectResponse response) {
        if (!(MetadataKeyConstants.isV1Format(metadata) || MetadataKeyConstants.isV2Format(metadata))) {
            //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //# In general, if there is any deviation from the above format, with the exception of additional unrelated mapkeys, then the S3EC SHOULD throw an exception.
            throw new S3EncryptionClientException("Content metadata is tampered, required metadata to decrypt the object are missing");
        }

        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //# - The mapkey "x-amz-cek-alg" MUST be present for V2 format objects.
        final String contentEncryptionAlgorithm = metadata.get(MetadataKeyConstants.CONTENT_CIPHER);
        AlgorithmSuite algorithmSuite;

        String contentRange = response.contentRange();
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //= type=exception
        //# - The mapkey "x-amz-unencrypted-content-length" SHOULD be present for V1 format objects.
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys

        //# - The mapkey "x-amz-cek-alg" MUST be present for V2 format objects.
        if (contentEncryptionAlgorithm == null
                || contentEncryptionAlgorithm.equals(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF.cipherName())) {
            algorithmSuite = AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF;
        } else if (contentEncryptionAlgorithm.equals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherName())) {
            //= specification/s3-encryption/decryption.md#ranged-gets
            //# If the object was encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF, then
            //# ALG_AES_256_CTR_IV16_TAG16_NO_KDF MUST be used to decrypt the range of the object.
            algorithmSuite = (contentRange == null)
                    ? AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
                    : AlgorithmSuite.ALG_AES_256_CTR_IV16_TAG16_NO_KDF;
        } else {
            throw new S3EncryptionClientException(
                    "Unknown content encryption algorithm for V2 message format: " + contentEncryptionAlgorithm);
        }

        // Do algorithm suite dependent decoding
        byte[] edkCiphertext;

        // Currently, this is not stored within the metadata,
        // signal to keyring(s) intended for S3EC
        final String keyProviderId = S3Keyring.KEY_PROVIDER_ID;
        String keyProviderInfo;
        switch (algorithmSuite) {
            case ALG_AES_256_CBC_IV16_NO_KDF:
                //= specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
                //# Objects encrypted with ALG_AES_256_CBC_IV16_NO_KDF MAY use either the V1 or V2 message format version.
                if (metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V1)) {
                    //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                    //# - The mapkey "x-amz-key" MUST be present for V1 format objects.
                    edkCiphertext = DECODER.decode(metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V1));
                } else if (metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2)) {
                    //= specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
                    //# Objects encrypted with ALG_AES_256_CBC_IV16_NO_KDF MAY use either the V1 or V2 message format version.
                    //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                    //# - The mapkey "x-amz-key-v2" MUST be present for V2 format objects.
                    edkCiphertext = DECODER.decode(metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2));
                } else {
                    // this shouldn't happen under normal circumstances- only if out-of-band modification
                    // to the metadata is performed. it is most likely that the data is unrecoverable in this case
                    throw new S3EncryptionClientException("Malformed object metadata! Could not find the encrypted data key.");
                }

                //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-wrap-alg" MUST be present for V2 format objects.
                if (!metadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM)) {
                    /*
                    For legacy v1 EncryptionOnly objects,
                    there is no EDK algorithm given, it is either plain AES or RSA
                    In v3, we infer AES vs. RSA based on the length of the ciphertext.

                    In v1, whichever key material is provided in its EncryptionMaterials
                    is used to decrypt the EDK.

                    In v3, this is not possible as the keyring code is factored such that
                    the keyProviderInfo is known before the keyring is known.
                    Ciphertext size is expected to be reliable as no AES data key should
                    exceed 256 bits (32 bytes) + 16 padding bytes.

                    In the unlikely event that this assumption is false, the fix would be
                    to refactor the keyring to always use the material given instead of
                    inferring it this way.
                    */
                    if (edkCiphertext.length > 48) {
                        keyProviderInfo = "RSA";
                    } else {
                        keyProviderInfo = "AES";
                    }
                } else {
                    keyProviderInfo = metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM);
                }
                break;
            case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
            case ALG_AES_256_CTR_IV16_TAG16_NO_KDF:
                //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-tag-len" MUST be present for V2 format objects.
                final int tagLength = Integer.parseInt(metadata.get(MetadataKeyConstants.CONTENT_CIPHER_TAG_LENGTH));
                if (tagLength != algorithmSuite.cipherTagLengthBits()) {
                    throw new S3EncryptionClientException("Expected tag length (bits) of: "
                            + algorithmSuite.cipherTagLengthBits()
                            + ", got: " + tagLength);
                }

                //= specification/s3-encryption/data-format/content-metadata.md#algorithm-suite-and-message-format-version-compatibility
                //# Objects encrypted with ALG_AES_256_GCM_IV12_TAG16_NO_KDF MUST use the V2 message format version only.
                //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-key-v2" MUST be present for V2 format objects.
                edkCiphertext = DECODER.decode(metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2));
                //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
                //# - The mapkey "x-amz-wrap-alg" MUST be present for V2 format objects.
                keyProviderInfo = metadata.get(MetadataKeyConstants.ENCRYPTED_DATA_KEY_ALGORITHM);

                break;
            default:
                throw new S3EncryptionClientException(
                        "Unknown content encryption algorithm: " + algorithmSuite.id());
        }

        // Build encrypted data key
        EncryptedDataKey edk = EncryptedDataKey.builder()
                .encryptedDataKey(edkCiphertext)
                .keyProviderId(keyProviderId)
                .keyProviderInfo(keyProviderInfo)
                .build();

        // Get encrypted data key encryption context or materials description (depending on the keyring)
        // The V2 client treats null value here as empty, do the same to avoid incompatibility

        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //# - The mapkey "x-amz-matdesc" MUST be present for V1 format objects.
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //# - The mapkey "x-amz-matdesc" MUST be present for V2 format objects.
        String jsonEncryptionContext = metadata.getOrDefault(MetadataKeyConstants.ENCRYPTED_DATA_KEY_MATDESC_OR_EC, "{}");
        //= specification/s3-encryption/data-format/content-metadata.md#v1-v2-shared
        //= type=implication
        //# This string MAY be encoded by the esoteric double-encoding scheme used by the S3 web server.
        final Map<String, String> matDescMap = decodeAndParseJsonString(jsonEncryptionContext);

        // By default, assume the context is a materials description unless it's a KMS keyring
        Map<String, String> encryptionContext;
        MaterialsDescription materialsDescription;

        if (keyProviderInfo.contains("kms")) {
            // For KMS keyrings, use the map as encryption context
            encryptionContext = matDescMap;
            materialsDescription = MaterialsDescription.builder().build();
        } else {
            // For all other keyrings (AES, RSA), use the map as materials description
            materialsDescription = MaterialsDescription.builder()
                    .putAll(matDescMap)
                    .build();
            // Set an empty encryption context
            encryptionContext = new HashMap<>();
        }

        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //# - The mapkey "x-amz-iv" MUST be present for V1 format objects.
        //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
        //# - The mapkey "x-amz-iv" MUST be present for V2 format objects.
        byte[] iv = DECODER.decode(metadata.get(MetadataKeyConstants.CONTENT_IV));

        return ContentMetadata.builder()
                .algorithmSuite(algorithmSuite)
                .encryptedDataKey(edk)
                .encryptionContext(encryptionContext)
                .materialsDescription(materialsDescription)
                .contentIv(iv)
                .contentRange(contentRange)
                .build();
    }

    /**
     * Loads metadata from the instruction file and returns it as a map.
     *
     * @param request the original GetObject request
     * @return the metadata map loaded from the instruction file
     * @throws S3EncryptionClientException if the instruction file cannot be loaded or parsed
     */
    public Map<String, String> loadInstructionFileMetadata(GetObjectRequest request) {
        String instructionFileSuffix = request.overrideConfiguration()
                .flatMap(config -> config.executionAttributes().getOptionalAttribute(S3EncryptionClient.CUSTOM_INSTRUCTION_FILE_SUFFIX))
                .orElse(DEFAULT_INSTRUCTION_FILE_SUFFIX);

        GetObjectRequest instructionGetObjectRequest = GetObjectRequest.builder()
                .bucket(request.bucket())
                .key(request.key() + instructionFileSuffix)
                .build();

        ResponseInputStream<GetObjectResponse> instruction;
        try {
            instruction = instructionFileConfig_.getInstructionFile(instructionGetObjectRequest);
        } catch (CompletionException | S3EncryptionClientException | NoSuchKeyException exception) {
            // This happens when the customer is attempting to decrypt an object
            // which is not encrypted with the S3 EC,
            // or instruction files are disabled,
            // or the instruction file is lost.
            throw new S3EncryptionClientException("Exception encountered while fetching Instruction File. Ensure the object you are" +
                    " attempting to decrypt has been encrypted using the S3 Encryption Client and instruction files are enabled.", exception);
        }

        Map<String, String> metadata = new HashMap<>();
        JsonNodeParser parser = JsonNodeParser.create();
        JsonNode objectNode = parser.parse(instruction);
        for (Map.Entry<String, JsonNode> entry : objectNode.asObject().entrySet()) {
            metadata.put(entry.getKey(), entry.getValue().asString());
        }
        return metadata;
    }

    /**
     * Determines if V1/V2 format is present in object metadata.
     * All V1/V2 keys must be present in object metadata.
     */
    public static boolean isV1V2InObjectMetadata(Map<String, String> objectMetadata) {
        //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //# - If the metadata contains "x-amz-iv" and "x-amz-key" then the object MUST be considered as an S3EC-encrypted object using the V1 format.
        //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //# - If the metadata contains "x-amz-iv" and "x-amz-metadata-x-amz-key-v2" then the object MUST be considered as an S3EC-encrypted object using the V2 format.
        return objectMetadata.containsKey(MetadataKeyConstants.CONTENT_IV)
                && (objectMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V1)
                || objectMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V2));
    }

    /**
     * Determines if V3 format is present in object metadata.
     * "x-amz-c" and "x-amz-d" and "x-amz-i" keys are always in object metadata, and "x-amz-3" is also in object metadata.
     */
    public static boolean isV3InObjectMetadata(Map<String, String> objectMetadata) {
        //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //# - If the metadata contains "x-amz-3" and "x-amz-d" and "x-amz-i" then the object MUST be considered an S3EC-encrypted object using the V3 format.
        return objectMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V3)
                && objectMetadata.containsKey(MetadataKeyConstants.KEY_COMMITMENT_V3)
                && objectMetadata.containsKey(MetadataKeyConstants.MESSAGE_ID_V3)
                && objectMetadata.containsKey(MetadataKeyConstants.CONTENT_CIPHER_V3);
    }

    /**
     * Determines if V3 format uses instruction file.
     * "x-amz-c" and "x-amz-d" and "x-amz-i" are in object metadata, but "x-amz-3" is not present (must be in instruction file).
     */
    public static boolean isV3InInstructionFile(Map<String, String> objectMetadata) {
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //# - The V3 message format MUST store the mapkey "x-amz-c" and its value in the Object Metadata when writing with an Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //# - The V3 message format MUST store the mapkey "x-amz-d" and its value in the Object Metadata when writing with an Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //# - The V3 message format MUST store the mapkey "x-amz-i" and its value in the Object Metadata when writing with an Instruction File.
        return objectMetadata.containsKey(MetadataKeyConstants.CONTENT_CIPHER_V3)
                && objectMetadata.containsKey(MetadataKeyConstants.KEY_COMMITMENT_V3)
                && objectMetadata.containsKey(MetadataKeyConstants.MESSAGE_ID_V3)
                && !objectMetadata.containsKey(MetadataKeyConstants.ENCRYPTED_DATA_KEY_V3);
    }

    /**
     * Decodes V1/V2 format from instruction file.
     * No V1/V2 keys in object metadata, all keys are in instruction file.
     */
    public ContentMetadata decodeV1V2FromInstructionFile(GetObjectRequest request, GetObjectResponse response) {
        //= specification/s3-encryption/data-format/metadata-strategy.md#v1-v2-instruction-files
        //# In the V1/V2 message format, all of the content metadata MUST be stored in the Instruction File.
        Map<String, String> instructionFileMetadata = loadInstructionFileMetadata(request);
        return readFromMapV1V2(instructionFileMetadata, response);
    }

    /**
     * Decodes V3 format from instruction file.
     * c/d/i keys are in object metadata, x-amz-3 and other keys are in instruction file.
     */
    public ContentMetadata decodeV3FromInstructionFile(GetObjectRequest request, GetObjectResponse response) {
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //# - The V3 message format MUST store the mapkey "x-amz-3" and its value in the Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //# - The V3 message format MUST store the mapkey "x-amz-w" and its value in the Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //# - The V3 message format MUST store the mapkey "x-amz-m" and its value (when present in the content metadata) in the Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //# - The V3 message format MUST store the mapkey "x-amz-t" and its value (when present in the content metadata) in the Instruction File.
        Map<String, String> instructionFileMetadata = loadInstructionFileMetadata(request);

        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //# - The V3 message format MUST NOT store the mapkey "x-amz-c" and its value in the Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //# - The V3 message format MUST NOT store the mapkey "x-amz-d" and its value in the Instruction File.
        //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
        //# - The V3 message format MUST NOT store the mapkey "x-amz-i" and its value in the Instruction File.
        if (instructionFileMetadata.containsKey(MetadataKeyConstants.CONTENT_CIPHER_V3) ||
                instructionFileMetadata.containsKey(MetadataKeyConstants.KEY_COMMITMENT_V3) ||
                instructionFileMetadata.containsKey(MetadataKeyConstants.MESSAGE_ID_V3)) {
            throw new S3EncryptionClientSecurityException("Instruction file is tampered, instruction file contains object metadata exclusive mapkeys");
        }

        // For V3 instruction files, merge the c/d/i keys from object metadata
        Map<String, String> mergedMetadata = new HashMap<>(instructionFileMetadata);
        mergedMetadata.put(MetadataKeyConstants.CONTENT_CIPHER_V3, response.metadata().get(MetadataKeyConstants.CONTENT_CIPHER_V3));
        mergedMetadata.put(MetadataKeyConstants.KEY_COMMITMENT_V3, response.metadata().get(MetadataKeyConstants.KEY_COMMITMENT_V3));
        mergedMetadata.put(MetadataKeyConstants.MESSAGE_ID_V3, response.metadata().get(MetadataKeyConstants.MESSAGE_ID_V3));

        return readFromV3FormatMap(mergedMetadata, response);
    }

    public ContentMetadata decode(GetObjectRequest request, GetObjectResponse response) {
        Map<String, String> objectMetadata = response.metadata();

        //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //= type=exception
        //# If there are multiple mapkeys which are meant to be exclusive, such as "x-amz-key", "x-amz-key-v2", and "x-amz-3" then the S3EC SHOULD throw an exception.

        if (objectMetadata != null) {
            // V1/V2 in Object Metadata - All V1/V2 keys present in object metadata
            //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //# - If the metadata contains "x-amz-iv" and "x-amz-key" then the object MUST be considered as an S3EC-encrypted object using the V1 format.
            //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //# - If the metadata contains "x-amz-iv" and "x-amz-metadata-x-amz-key-v2" then the object MUST be considered as an S3EC-encrypted object using the V2 format.
            if (isV1V2InObjectMetadata(objectMetadata)) {
                return readFromMapV1V2(objectMetadata, response);
            }

            // V3 in Object Metadata - c/d/i always in object metadata, x-amz-3 also in object metadata
            //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
            //# - If the metadata contains "x-amz-3" and "x-amz-d" and "x-amz-i" then the object MUST be considered an S3EC-encrypted object using the V3 format.
            //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
            else if (isV3InObjectMetadata(objectMetadata)) {
                return readFromV3FormatMap(objectMetadata, response);
            }

            // V3 in Instruction File - "x-amz-c" and "x-amz-d" and "x-amz-i" in object metadata, but x-amz-3 not present (must be in instruction file)
            //= specification/s3-encryption/data-format/content-metadata.md#content-metadata-mapkeys
            //# In the V3 format, the mapkeys "x-amz-c", "x-amz-d", and "x-amz-i" MUST be stored exclusively in the Object Metadata.
            //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-c" and its value in the Object Metadata when writing with an Instruction File.
            //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-d" and its value in the Object Metadata when writing with an Instruction File.
            //= specification/s3-encryption/data-format/metadata-strategy.md#v3-instruction-files
            //# - The V3 message format MUST store the mapkey "x-amz-i" and its value in the Object Metadata when writing with an Instruction File.
            else if (isV3InInstructionFile(objectMetadata)) {
                return decodeV3FromInstructionFile(request, response);
            }
        }

        // V1/V2 in Instruction File - No V1/V2 keys in object metadata, all in instruction file
        //= specification/s3-encryption/data-format/content-metadata.md#determining-s3ec-object-status
        //= type=implication
        //# If the object matches none of the V1/V2/V3 formats, the S3EC MUST attempt to get the instruction file.
        return decodeV1V2FromInstructionFile(request, response);
    }
}
