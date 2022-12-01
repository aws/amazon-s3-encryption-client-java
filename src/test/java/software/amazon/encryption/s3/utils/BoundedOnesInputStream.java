package software.amazon.encryption.s3.utils;

import java.io.InputStream;

/**
 * Test utility class.
 * Stream of a fixed number of ones. Useful for testing
 * stream uploads of a specific size. Not threadsafe.
 */
public class BoundedOnesInputStream extends InputStream {

    private final long _bound;
    private long _progress = 0;

    public BoundedOnesInputStream(final long bound) {
        _bound = bound;
    }

    @Override
    public int read() {
        if (_progress >= _bound) {
            return -1;
        }
        _progress++;
        return 1;
    }



}

