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
package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientSecurityException;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

public class AuthenticatedCipherInputStream extends CipherInputStream {

    /**
     * True if this input stream is currently involved in a multipart uploads;
     * false otherwise. For multipart uploads, the doFinal method of the
     * underlying cipher has to be triggered via the read methods rather than
     * the close method, since we can't tell if closing the input stream is due
     * to a recoverable error (in which case the cipher's doFinal method should
     * never be called) or normal completion (where the cipher's doFinal method
     * would need to be called if it was not a multipart upload).
     */
    private final boolean multipart;
    /**
     * True if this is the last part of a multipart upload; false otherwise.
     */
    private final boolean lastMultipart;

    public AuthenticatedCipherInputStream(InputStream inputStream, Cipher cipher) {
        this(inputStream, cipher, false, false);
    }

    public AuthenticatedCipherInputStream(InputStream inputStream, Cipher cipher,
                                          boolean multipart, boolean lastMultipart) {
        super(inputStream, cipher);
        this.multipart = multipart;
        this.lastMultipart = lastMultipart;
    }
    
    /**
     * Authenticated ciphers call doFinal upon the last read,
     * there is no need to do so upon close.
     * @throws IOException from the wrapped InputStream
     */
    @Override
    public void close() throws IOException {
        in.close();
        currentPosition = maxPosition = 0;
        abortIfNeeded();
    }

    @Override
    protected int endOfFileReached() {
        eofReached = true;
        // Skip doFinal if it's a multipart upload but not for the last part of multipart upload
        if (!multipart || lastMultipart) {
            try {
                outputBuffer = cipher.doFinal();
                if (outputBuffer == null) {
                    return -1;
                }
                currentPosition = 0;
                return maxPosition = outputBuffer.length;
            } catch (GeneralSecurityException exception) {
                // In an authenticated scheme, this indicates a security
                // exception
                throw new S3EncryptionClientSecurityException(exception.getMessage(), exception);
            }
        }
        return -1;
    }
}
