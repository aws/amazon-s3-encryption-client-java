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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Reads an InputStream instances into memory.
 */
public class BoundedStreamBufferer {

    public static byte[] toByteArray(InputStream is, int bufferSize) throws IOException {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] b = new byte[bufferSize];
            int n;
            while ((n = is.read(b)) != -1) {
                output.write(b, 0, n);
            }
            return output.toByteArray();
        }
    }

    public static byte[] toByteArrayWithMarkReset(InputStream is, int bufferSize) throws IOException {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] b = new byte[bufferSize];
            // burn some bytes to force mark/reset
            byte[] discard = new byte[bufferSize];
            int n;
            while ((n = is.read(b)) != -1) {
                is.mark(bufferSize);
                is.read(discard, 0, bufferSize);
                is.reset();
                output.write(b, 0, n);
            }
            return output.toByteArray();
        }
    }
}
