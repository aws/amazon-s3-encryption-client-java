/*
 * Copyright 2013-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.algorithms.AlgorithmSuite;
import software.amazon.encryption.s3.materials.CryptographicMaterials;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NullCipher;
import javax.crypto.SecretKey;

/**
 * Functions like a {@link Cipher} but provides only a subset of all the
 * interface methods of {@link Cipher}. This class is intended to be used in
 * lieu of the underlying Cipher directly whenever applicable. For example, this
 * class makes it easy to generate an inverse cipher, or to create an
 * "auxiliary" cipher for use with get-range or multi-part upload operations. A
 * subclass may also support the mark and reset operations to enable parts of a
 * plaintext to be re-processed which is useful for error recovery typical when
 * network transmission is involved.
 * <p>
 * However a cipher lite, unlike a {@link Cipher}, can only be used once, and
 * cannot be reused after the {@link #doFinal()} methods have been invoked. In
 * other words, it is NOT true that, upon finishing, the doFinal method will
 * reset the cipher lite object to the state it was in when first constructed.
 *
 //* @see GCMCipherLite
 */
public class CipherLite {
    /**
     * A no-op implementation.
     */
    public static final CipherLite Null = new CipherLite() {
        @Override
        public CipherLite createAuxiliary(long startingBytePos) {
            return this;
        }
    };
    private final Cipher cipher;
    private final CryptographicMaterials materials;
    private final SecretKey secretKey;
    private final int cipherMode;
    // For some reason, Cipher returns a null IV once initialized.
    // In order to recreate the CipherLite, store the IV here too.
    private final byte[] iv;

    private CipherLite() {
        this.cipher = new NullCipher();
        this.materials = null;
        this.secretKey = null;
        this.cipherMode = -1;
        this.iv = null;
    }

    CipherLite(Cipher cipher, CryptographicMaterials materials,
               SecretKey secretKey, int cipherMode, byte[] nonce) {
        this.cipher = cipher;
        this.materials = materials;
        this.secretKey = secretKey;
        this.cipherMode = cipherMode;
        this.iv = nonce;
    }

    /**
     * Recreates a new instance of CipherLite from the current one.
     */
    public CipherLite recreate() {
        return CipherLiteFactory.newGcmCipherLite(secretKey, iv, cipherMode, cipher.getProvider(),
                true, materials);
    }

    /**
     * Returns an auxiliary {@link CipherLite} for partial plaintext
     * re-encryption (or re-decryption) purposes.
     *
     * @param startingBytePos
     *            the starting byte position of the plaintext. Must be a
     *            multiple of the cipher block size.
     */
    public CipherLite createAuxiliary(long startingBytePos) {
        return CipherLiteFactory.createAuxiliaryCipher(secretKey, iv, cipherMode, cipher.getProvider(),
                startingBytePos, materials);
    }

    /**
     * Finishes a multiple-part encryption or decryption operation, depending on
     * how the underlying cipher was initialized.
     *
     * <p>
     * Input data that may have been buffered during a previous
     * <code>update</code> operation is processed, with padding (if requested)
     * being applied. If an AEAD mode such as GCM/CCM is being used, the
     * authentication tag is appended in the case of encryption, or verified in
     * the case of decryption. The result is stored in a new buffer.
     *
     * <p>
     * Note: if any exception is thrown, a new instance of this cipher lite
     * object may need to be constructed before it can be used again. be
     * reconstructed before it can be used again.
     *
     * @return the new buffer with the result
     *
     * @exception IllegalStateException
     *                if this cipher is in a wrong state (e.g., has not been
     *                initialized)
     * @exception IllegalBlockSizeException
     *                if this cipher is a block cipher, no padding has been
     *                requested (only in encryption mode), and the total input
     *                length of the data processed by this cipher is not a
     *                multiple of block size; or if this encryption algorithm is
     *                unable to process the input data provided.
     * @exception BadPaddingException
     *                if this cipher is in decryption mode, and (un)padding has
     *                been requested, but the decrypted data is not bounded by
     *                the appropriate padding bytes
     * @exception javax.crypto.AEADBadTagException
     *                if this cipher is decrypting in an AEAD mode (such as
     *                GCM/CCM), and the received authentication tag does not
     *                match the calculated value
     */
    public byte[] doFinal() throws IllegalBlockSizeException,
            BadPaddingException {
        return cipher.doFinal();
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted, depending on
     * how the underlying cipher was initialized.
     *
     * <p>
     * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
     * starting at <code>inputOffset</code> inclusive, and any input bytes that
     * may have been buffered during a previous <code>update</code> operation,
     * are processed, with padding (if requested) being applied. If an AEAD mode
     * such as GCM/CCM is being used, the authentication tag is appended in the
     * case of encryption, or verified in the case of decryption. The result is
     * stored in a new buffer.
     *
     * <p>
     * Note: if any exception is thrown, a new instance of this cipher lite
     * object may need to be constructed before it can be used again.
     *
     * @param input
     *            the input buffer
     * @param inputOffset
     *            the offset in <code>input</code> where the input starts
     * @param inputLen
     *            the input length
     *
     * @return the new buffer with the result
     *
     * @exception IllegalStateException
     *                if this cipher is in a wrong state (e.g., has not been
     *                initialized)
     * @exception IllegalBlockSizeException
     *                if this cipher is a block cipher, no padding has been
     *                requested (only in encryption mode), and the total input
     *                length of the data processed by this cipher is not a
     *                multiple of block size; or if this encryption algorithm is
     *                unable to process the input data provided.
     * @exception BadPaddingException
     *                if this cipher is in decryption mode, and (un)padding has
     *                been requested, but the decrypted data is not bounded by
     *                the appropriate padding bytes; or if this cipher is
     *                decrypting in an AEAD mode (such as GCM/CCM), and the
     *                received authentication tag does not match the calculated
     *                value
     */
    public byte[] doFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        return cipher.doFinal(input, inputOffset, inputLen);
    }

    /**
     * Continues a multiple-part encryption or decryption operation (depending
     * on how the underlying cipher was initialized), processing another data
     * part.
     *
     * <p>
     * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
     * starting at <code>inputOffset</code> inclusive, are processed, and the
     * result is stored in a new buffer.
     *
     * <p>
     * If <code>inputLen</code> is zero, this method returns <code>null</code>.
     *
     * @param input
     *            the input buffer
     * @param inputOffset
     *            the offset in <code>input</code> where the input starts
     * @param inputLen
     *            the input length
     *
     * @return the new buffer with the result, or null if the underlying cipher
     *         is a block cipher and the input data is too short to result in a
     *         new block.
     *
     * @exception IllegalStateException
     *                if the underlying cipher is in a wrong state (e.g., has
     *                not been initialized)
     */
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        return cipher.update(input, inputOffset, inputLen);
    }

    public final boolean isCipherAlgorithmAesGcm() {
        return cipher.getAlgorithm().equals(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherName());
    }

    final int getCipherMode() {
        return cipherMode;
    }

    /**
     * Tests if this cipher lite supports the <code>mark</code>
     * and <code>reset</code> methods.  Returns false by default, but subclass
     * may override.
     */
    public boolean markSupported() { return false; }

    /**
     * Marks the current position in this cipher lite. A subsequent call to the
     * <code>reset</code> method repositions this cipher lite at the last marked
     * position so that subsequent crypto operations will be logically performed
     * in an idempotent manner as if the cipher has been rewinded back to the
     * marked position.
     *
     * <p>
     * The general contract of <code>mark</code> is that, if the method
     * <code>markSupported</code> returns <code>true</code>, the cipher lite
     * somehow remembers the internal state after the call to <code>mark</code>
     * and stands ready to restore to the internal state so that it would be
     * able to produce the same output given the same input again if and
     * whenever the method <code>reset</code> is called.
     *
     * @return the current position marked or -1 if mark/reset is not supported.
     */
    public long mark() { return -1; }

    /**
     * Repositions this cipher lite to the position at the time the
     * <code>mark</code> method was last called.
     *
     * <p>
     * The general contract of <code>reset</code> is:
     *
     * <p>
     * <ul>
     * <li>If the method <code>markSupported</code> returns <code>true</code>,
     * then the cipher lite is reset to the internal state since the most recent
     * call to <code>mark</code> (or since the start of the input data, if
     * <code>mark</code> has not been called), so that subsequent callers of the
     * <code>udpate</code> or <code>doFinal</code> method would produce the same
     * output given the same input data identical to the input data after the
     * <code>mark</code> method was last called..</li>
     *
     * <li>If the method <code>markSupported</code> returns <code>false</code>,
     * then the call to <code>reset</code> may throw an
     * <code>IllegalStateException</code>.</li>
     * </ul>
     */
    public void reset() {
        throw new IllegalStateException("mark/reset not supported");
    }

}
