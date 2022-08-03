package software.amazon.encryption.s3.algorithms;

class AlgorithmConstants {
    // Maximum length of the content that can be encrypted in GCM mode.
    static final long GCM_MAX_CONTENT_LENGTH_BITS = (1L<<39) - 256;

    // Maximum length of the content that can be encrypted in CBC mode.
    static final long CBC_MAX_CONTENT_LENGTH_BYTES = (1L<<55);
}
