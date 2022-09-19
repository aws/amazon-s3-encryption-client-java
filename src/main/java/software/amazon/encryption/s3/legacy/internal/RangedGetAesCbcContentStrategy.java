package software.amazon.encryption.s3.legacy.internal;

import software.amazon.encryption.s3.internal.ContentDecryptionStrategy;
import software.amazon.encryption.s3.internal.ContentMetadata;
import software.amazon.encryption.s3.materials.DecryptionMaterials;

import java.io.InputStream;

/**
 * Content strategy which supports "ranged get" functionality.
 * A ranged get returns only part of the data of an object in S3.
 * Content encrypted with AES-CBC will be decrypted with AES-CBC.
 */
public class RangedGetAesCbcContentStrategy implements ContentDecryptionStrategy {
    @Override
    public InputStream decryptContent(ContentMetadata contentMetadata, DecryptionMaterials materials, InputStream ciphertext) {
        throw new UnsupportedOperationException("Ranged gets are not yet supported.");
    }
}
