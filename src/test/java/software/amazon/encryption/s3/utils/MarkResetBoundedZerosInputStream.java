// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.utils;

import java.io.InputStream;

/**
 * Test utility class.
 * Stream of a fixed number of zeros. Supports arbitrary mark/reset.
 * Useful for testing stream uploads of a specific size. Not threadsafe.
 */
public class MarkResetBoundedZerosInputStream extends InputStream {

    private final long _boundInBytes;
    private long _progress = 0;
    private long _mark = 0;

    public MarkResetBoundedZerosInputStream(final long boundInBytes) {
        _boundInBytes = boundInBytes;
    }

    @Override
    public int read() {
        if (_progress >= _boundInBytes) {
            return -1;
        }
        _progress++;
        return 0;
    }

    @Override
    public boolean markSupported() {
        return true;
    }

    @Override
    public void mark(int readLimit) {
        // Since this InputStream implementation is bounded, we can support
        // arbitrary mark/reset, so just discard the readLimit parameter.
        _mark = _progress;
    }

    @Override
    public void reset() {
        _progress = _mark;
        _mark = 0;
    }
}
