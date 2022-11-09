package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

public class CryptoProvider {
    public static final String BOUNCY_CASTLE_PROVIDER = "BC";
    private static final String BC_PROVIDER_FQCN = "org.bouncycastle.jce.provider.BouncyCastleProvider";

    public static boolean preferDefaultSecurityProvider() {
        final String preferDefaultSecurityProvider = System.getProperty("software.amazon.encryption.s3.internal.preferDefaultSecurityProvider");
        if (preferDefaultSecurityProvider == null) {
            return false;
        }
        return Boolean.parseBoolean(preferDefaultSecurityProvider);
    }


    public static Cipher createCipher(String algorithm, Provider provider) throws NoSuchPaddingException, NoSuchAlgorithmException {
        if (provider == null) {
            return Cipher.getInstance(algorithm);
        }
        else {
            return Cipher.getInstance(algorithm, provider);
        }
    }

    public static Cipher createCipher(String algorithm, Provider provider, boolean alwaysUseProvider)
            throws GeneralSecurityException {

        // If the user has specified that they always want to use the provider they
        // specified, that wins (this is not the default for backwards compatibility
        // reasons).
        if (alwaysUseProvider) {
            return Cipher.getInstance(algorithm, provider);
        }

        // Otherwise, if the user has specified a global preference for the default Provider chain, that takes precedence.
        if (preferDefaultSecurityProvider()) {
            return Cipher.getInstance(algorithm);
        }

        // Otherwise, if this crypto scheme prefers a particular provider (AesGcm prefers
        // the non-FIPS BouncyCastle provider), that takes precedence.
        if (algorithm == AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherName()) {
            return Cipher.getInstance(algorithm, BOUNCY_CASTLE_PROVIDER);
        }

        // Otherwise, if the user has specified a provider, go with that.
        if (provider != null) {
            return Cipher.getInstance(algorithm, provider);
        }

        // If all else fails, go with the default provider.
        return Cipher.getInstance(algorithm);
    }

    public static void checkBountyCastle() {
        if (!isBouncyCastleAvailable()) {
            enableBouncyCastle();
            if (!isBouncyCastleAvailable()) {
                throw new UnsupportedOperationException(
                        "The Bouncy castle library jar is required on the classpath to enable authenticated encryption");
            }
        }
        if (!isAesGcmAvailable())
            throw new UnsupportedOperationException(
                    "A more recent version of Bouncy castle is required for authenticated encryption.");
    }

    public static boolean isAesGcmAvailable() { return checkAesGcmAvailable(); }
    public static void recheckAesGcmAvailablility() { checkAesGcmAvailable(); }

    private static boolean checkAesGcmAvailable() {
        try {
            Cipher.getInstance(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherName(),
                    BOUNCY_CASTLE_PROVIDER);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    public static synchronized boolean isBouncyCastleAvailable() {
        return Security.getProvider(BOUNCY_CASTLE_PROVIDER) != null;
    }

    public static synchronized void enableBouncyCastle() {
        if (isBouncyCastleAvailable()) {
            return;
        }
        try {
            @SuppressWarnings("unchecked")
            Class<Provider> c = (Class<Provider>) Class.forName(BC_PROVIDER_FQCN);
            Provider provider = c.newInstance();
            Security.addProvider(provider);
        } catch (ClassNotFoundException| InstantiationException | IllegalAccessException e) {
            throw new RuntimeException("Bouncy Castle not available" + e.getMessage());
        }
    }
}
