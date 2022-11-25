package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.materials.EncryptionMaterials;

import java.util.Map;

public interface ContentMetadataEncodingStrategy {

    Map<String, String> encodeMetadata(EncryptionMaterials materials, byte[] nonce,
                                              Map<String, String> metadata);
}
