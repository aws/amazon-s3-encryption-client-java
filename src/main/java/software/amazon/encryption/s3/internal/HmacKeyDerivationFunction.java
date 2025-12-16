package software.amazon.encryption.s3.internal;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;

/**
 * HMAC-based Key Derivation Function. Adapted from HmacKeyDerivationFunction.java in
 * aws-encryption-sdk-java
 *
 * @see <a href="http://tools.ietf.org/html/rfc5869">RFC 5869</a>
 */
public final class HmacKeyDerivationFunction {
    private static final byte[] EMPTY_ARRAY = new byte[0];
    private final String algorithm;
    private final Provider provider;
    private SecretKey prk = null;

    /**
     * Returns an <code>HmacKeyDerivationFunction</code> object using the specified algorithm.
     *
     * @param algorithm the standard name of the requested MAC algorithm. See the Mac section in the
     *                  <a href=
     *                  "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac" >
     *                  Java Cryptography Architecture Standard Algorithm Name Documentation</a> for information
     *                  about standard algorithm names.
     * @param provider the user specified provider.
     * @return the new <code>Hkdf</code> object
     * @throws NoSuchAlgorithmException if no Provider supports a MacSpi implementation for the
     *                                  specified algorithm.
     */
    public static HmacKeyDerivationFunction getInstance(final String algorithm, final Provider provider)
            throws NoSuchAlgorithmException {
        // Constructed specifically to sanity-test arguments.
        Mac mac;
        if (provider != null) {
            // if the user has specified a provider, go with that.
            mac = Mac.getInstance(algorithm, provider);
        } else {
            // Otherwise, go with the default provider.
            mac = Mac.getInstance(algorithm);
        }
        return new HmacKeyDerivationFunction(algorithm, mac.getProvider());
    }

    /**
     * Initializes this Hkdf with input keying material. A default salt of HashLen zeros will be used
     * (where HashLen is the length of the return value of the supplied algorithm).
     *
     * @param ikm the Input Keying Material
     */
    public void init(final byte[] ikm) {
        init(ikm, null);
    }

    /**
     * Initializes this Hkdf with input keying material and a salt. If <code>
     * salt</code> is <code>null</code> or of length 0, then a default salt of HashLen zeros will be
     * used (where HashLen is the length of the return value of the supplied algorithm).
     *
     * @param salt the salt used for key extraction (optional)
     * @param ikm  the Input Keying Material
     */
    public void init(final byte[] ikm, final byte[] salt) {
        byte[] realSalt = (salt == null) ? EMPTY_ARRAY : salt.clone();
        byte[] rawKeyMaterial = EMPTY_ARRAY;
        try {
            Mac extractionMac = Mac.getInstance(algorithm, provider);
            if (realSalt.length == 0) {
                realSalt = new byte[extractionMac.getMacLength()];
                Arrays.fill(realSalt, (byte) 0);
            }
            extractionMac.init(new SecretKeySpec(realSalt, algorithm));
            rawKeyMaterial = extractionMac.doFinal(ikm);
            //= specification/s3-encryption/key-derivation.md#hkdf-operation
            //= type=implication
            //# - The CK input pseudorandom key MUST be the output from the extract step.
            //= specification/s3-encryption/key-derivation.md#hkdf-operation
            //= type=implication
            //# - The DEK input pseudorandom key MUST be the output from the extract step.
            this.prk = new SecretKeySpec(rawKeyMaterial, algorithm);
        } catch (GeneralSecurityException e) {
            // We've already checked all the parameters so no exceptions
            // should be possible here.
            throw new RuntimeException("Unexpected exception", e);
        } finally {
            Arrays.fill(rawKeyMaterial, (byte) 0); // Zeroize temporary array
        }
    }

    private void isTrue(final boolean expression, final String message, final Object... values) {
        if (!expression) {
            throw new IllegalArgumentException(String.format(message, values));
        }

    }

    private HmacKeyDerivationFunction(final String algorithm, final Provider provider) {
        isTrue(
                algorithm.startsWith("Hmac"),
                "Invalid algorithm " + algorithm + ". Hkdf may only be used with Hmac algorithms.");
        this.algorithm = algorithm;
        this.provider = provider;
    }

    /**
     * Returns a pseudorandom key of <code>length</code> bytes.
     *
     * @param info   optional context and application specific information (can be a zero-length array).
     * @param length the length of the output key in bytes
     * @return a pseudorandom key of <code>length</code> bytes.
     * @throws IllegalStateException if this object has not been initialized
     */
    public byte[] deriveKey(final byte[] info, final int length) throws IllegalStateException {
        isTrue(length >= 0, "Length must be a non-negative value.");
        assertInitialized();
        final byte[] result = new byte[length];
        Mac mac = createMac();

        isTrue(
                length <= 255 * mac.getMacLength(),
                "Requested keys may not be longer than 255 times the underlying HMAC length.");

        byte[] t = EMPTY_ARRAY;
        try {
            int loc = 0;
            byte i = 1;
            while (loc < length) {
                mac.update(t);
                mac.update(info);
                mac.update(i);
                t = mac.doFinal();

                for (int x = 0; x < t.length && loc < length; x++, loc++) {
                    result[loc] = t[x];
                }

                i++;
            }
        } finally {
            Arrays.fill(t, (byte) 0); // Zeroize temporary array
        }
        return result;
    }

    private Mac createMac() {
        try {
            Mac mac = Mac.getInstance(algorithm, provider);
            mac.init(prk);
            return mac;
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            // We've already validated that this algorithm/key is correct.
            throw new RuntimeException(ex);
        }
    }

    /**
     * Throws an <code>IllegalStateException</code> if this object has not been initialized.
     *
     * @throws IllegalStateException if this object has not been initialized
     */
    private void assertInitialized() throws IllegalStateException {
        if (prk == null) {
            throw new IllegalStateException("Hkdf has not been initialized");
        }
    }
}
