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
        // There are 95 printable ASCII characters, starting at 32
        // So take modulo 95 and add 32 to keep within that range
        return ((int) (_progress % 95)) + 32;
    }
}

