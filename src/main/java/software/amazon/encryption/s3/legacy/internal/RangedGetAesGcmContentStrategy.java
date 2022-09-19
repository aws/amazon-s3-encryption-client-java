package software.amazon.encryption.s3.legacy.internal;

import software.amazon.encryption.s3.internal.ContentDecryptionStrategy;
import software.amazon.encryption.s3.internal.ContentMetadata;
import software.amazon.encryption.s3.materials.DecryptionMaterials;

import java.io.InputStream;

/**
 * Content strategy which supports "ranged get" functionality.
 * A ranged get returns only part of the data of an object in S3.
 * For encrypted objects, you can still do ranged gets but with the
 * major caveat that you are bypassing all authentication on the ciphertext.
 * Content encrypted with AES-GCM will be decrypted with AES-CTR.
 */
public class RangedGetAesGcmContentStrategy implements ContentDecryptionStrategy {
    @Override
    public InputStream decryptContent(ContentMetadata contentMetadata, DecryptionMaterials materials, InputStream ciphertext) {
        throw new UnsupportedOperationException("Ranged gets are not yet supported.");
    }

}
