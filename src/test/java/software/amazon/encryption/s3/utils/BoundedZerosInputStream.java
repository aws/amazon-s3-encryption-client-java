package software.amazon.encryption.s3.utils;

import java.io.InputStream;

/**
 * Test utility class.
 * Stream of a fixed number of zeros. Useful for testing
 * stream uploads of a specific size. Not threadsafe.
 */
public class BoundedZerosInputStream extends InputStream {

    private final long _bound;
    private long _progress = 0;

    public BoundedZerosInputStream(final long bound) {
        _bound = bound;
    }

    @Override
    public int read() {
        if (_progress >= _bound) {
            System.out.println("bound reached! done reading");
            return -1;
        }
        _progress++;
        return 0;
    }
}

