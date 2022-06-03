package software.amazon.encryption.s3.algorithms;

class Constants {
    /** Maximum length of the content that can be encrypted in GCM mode. */
    public static final long GCM_MAX_CONTENT_LEN = (1L << 36) - 32;
}
