package software.amazon.encryption.s3.algorithms;

class Constants {
    // Maximum length of the content that can be encrypted in GCM mode.
    static final long GCM_MAX_CONTENT_LENGTH_BITS = (1L<<39) - 256;
}
