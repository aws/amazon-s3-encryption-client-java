package software.amazon.encryption.s3.legacy.internal;

import software.amazon.encryption.s3.internal.CipherLite;
import software.amazon.encryption.s3.internal.CipherLiteFactory;
import software.amazon.encryption.s3.internal.CipherLiteInputStream;
import software.amazon.encryption.s3.internal.ContentDecryptionStrategy;
import software.amazon.encryption.s3.internal.ContentMetadata;
import software.amazon.encryption.s3.materials.DecryptionMaterials;

import java.io.InputStream;

public class StreamingAesCbcContentStrategy implements ContentDecryptionStrategy {

    private StreamingAesCbcContentStrategy(Builder builder) {}

    public static Builder builder() { return new Builder(); }

    @Override
    public InputStream decryptContent(ContentMetadata contentMetadata, DecryptionMaterials materials, InputStream ciphertext) {
        return getCipherLiteInputStreamForDecryption(ciphertext, materials, contentMetadata.contentNonce());
    }

    private InputStream getCipherLiteInputStreamForDecryption(final InputStream inputStream, DecryptionMaterials materials, byte[] nonce) {
        final CipherLite cipherLite = CipherLiteFactory.newCipherLiteForCbcDecryption(materials, nonce);
        return new CipherLiteInputStream(inputStream, cipherLite);
    }

    public static class Builder {
        private Builder() {}

        public StreamingAesCbcContentStrategy build() {
            return new StreamingAesCbcContentStrategy(this);
        }
    }
}
