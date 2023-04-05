/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
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
