package software.amazon.encryption.s3.utils;

import java.io.InputStream;

/**
 * Test utility class.
 * Stream of a fixed number of printable ASCII characters.
 * Useful for testing stream uploads of a specific size.
 * Not threadsafe.
 */
public class BoundedInputStream extends InputStream {

    private final long _bound;
    private long _progress = 0;

    public BoundedInputStream(final long bound) {
        _bound = bound;
    }

    @Override
    public int read() {
        if (_progress >= _bound) {
            return -1;
        }
        _progress++;
        return ((int) (_progress % 95)) % 95 + 32;
    }
}

