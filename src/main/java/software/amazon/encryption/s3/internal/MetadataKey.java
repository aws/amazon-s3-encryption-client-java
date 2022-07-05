package software.amazon.encryption.s3.internal;

public class MetadataKey {
    public static final String ENCRYPTED_DATA_KEY = "x-amz-key-v2";
    // This is the name of the keyring/algorithm e.g. AES/GCM or kms+context
    public static final String ENCRYPTED_DATA_KEY_ALGORITHM = "x-amz-wrap-alg";
    public static final String ENCRYPTED_DATA_KEY_CONTEXT = "x-amz-matdesc";

    public static final String CONTENT_NONCE = "x-amz-iv";
    // This is usually an actual Java cipher e.g. AES/GCM/NoPadding
    public static final String CONTENT_CIPHER = "x-amz-cek-alg";
    public static final String CONTENT_CIPHER_TAG_LENGTH = "x-amz-tag-len";
}
