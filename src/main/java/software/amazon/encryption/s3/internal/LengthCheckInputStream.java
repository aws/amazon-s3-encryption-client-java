package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.io.SdkFilterInputStream;
import software.amazon.encryption.s3.S3EncryptionClientException;

import java.io.IOException;
import java.io.InputStream;

public class LengthCheckInputStream extends SdkFilterInputStream {
    public static final boolean INCLUDE_SKIPPED_BYTES = true;
    public static final boolean EXCLUDE_SKIPPED_BYTES = false;
    private final long expectedLength;
    private final boolean includeSkipped;
    private long dataLength;
    private long marked;
    private boolean resetSinceLastMarked;
    private int markCount;
    private int resetCount;

    public LengthCheckInputStream(final InputStream in, final long expectedLength, final boolean includeSkipped) {
        super(in);
        if (expectedLength < 0L) {
            throw new IllegalArgumentException();
        } else {
            this.expectedLength = expectedLength;
            this.includeSkipped = includeSkipped;
        }
    }

    public int read() throws IOException {
        int c = super.read();
        if (c >= 0) {
            ++this.dataLength;
        }

        this.checkLength(c == -1);
        return c;
    }

    public int read(byte[] b, int off, int len) throws IOException {
        int readLen = super.read(b, off, len);
        this.dataLength += readLen >= 0 ? (long)readLen : 0L;
        this.checkLength(readLen == -1);
        return readLen;
    }

    public void mark(int readlimit) {
        if (this.markSupported()) {
            super.mark(readlimit);
            this.marked = this.dataLength;
            ++this.markCount;
            this.resetSinceLastMarked = false;
        }

    }

    public void reset() throws IOException {
        if (this.markSupported()) {
            super.reset();
            this.dataLength = this.marked;
            ++this.resetCount;
            this.resetSinceLastMarked = true;
        } else {
            throw new IOException("Mark/reset not supported");
        }
    }

    private void checkLength(boolean eof) {
        if (eof) {
            if (this.dataLength != this.expectedLength) {
                throw new S3EncryptionClientException("Data read has a different length than the expected: " + this.diagnosticInfo());
            }
        } else if (this.dataLength > this.expectedLength) {
            throw new S3EncryptionClientException("More data read than expected: " + this.diagnosticInfo());
        }

    }

    private String diagnosticInfo() {
        return "dataLength=" + this.dataLength + "; expectedLength=" + this.expectedLength + "; includeSkipped=" + this.includeSkipped + "; in.getClass()=" + this.in.getClass() + "; markedSupported=" + this.markSupported() + "; marked=" + this.marked + "; resetSinceLastMarked=" + this.resetSinceLastMarked + "; markCount=" + this.markCount + "; resetCount=" + this.resetCount;
    }

    public long skip(long n) throws IOException {
        long skipped = super.skip(n);
        if (this.includeSkipped && skipped > 0L) {
            this.dataLength += skipped;
            this.checkLength(false);
        }

        return skipped;
    }
}
