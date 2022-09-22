package software.amazon.encryption.s3.internal;

import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.materials.CryptographicMaterials;
import software.amazon.encryption.s3.materials.DecryptionMaterials;
import software.amazon.encryption.s3.materials.EncryptionMaterials;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;

/**
 * Responsible for creating CipherLite instances.
 * Only/always use BC and GCMCipherLite.
 */
public class CipherLiteFactory {

    // TODO: See comment below. For now just prefer BC.
    private static final String PREFERRED_PROVIDER = "BC";

    public static CipherLite newCipherLiteForCbcDecryption(final DecryptionMaterials materials, final byte[] nonce) {
        return newCbcCipherLite(materials.dataKey(), nonce, Cipher.DECRYPT_MODE, Security.getProvider(PREFERRED_PROVIDER), true, materials);
    }

    public static CipherLite newCipherLiteForDecryption(final DecryptionMaterials materials, final byte[] nonce) {
        return newGcmCipherLite(materials.dataKey(), nonce, Cipher.DECRYPT_MODE, Security.getProvider(PREFERRED_PROVIDER), true, materials);
    }

    public static CipherLite newCipherLiteForEncryption(final EncryptionMaterials materials, final byte[] nonce) {
        return newGcmCipherLite(materials.dataKey(), nonce, Cipher.ENCRYPT_MODE, Security.getProvider(PREFERRED_PROVIDER), true, materials);
    }

    public static CipherLite newCbcCipherLite(SecretKey cek, byte[] iv, int cipherMode, Provider provider, boolean alwaysUseProvider,
                                              final CryptographicMaterials materials) {
        try {
            Cipher cipher = createCipher(provider, alwaysUseProvider, materials);
            cipher.init(cipherMode, cek, new IvParameterSpec(iv));
            return new CipherLite(cipher, materials, cek, cipherMode, iv);
        } catch (GeneralSecurityException e) {
            throw new S3EncryptionClientException("Unable to build cipher: " + e.getMessage()
                    + "\nMake sure you have the JCE unlimited strength policy files installed and "
                    + "configured for your JVM.", e);
        }
    }
    public static CipherLite newGcmCipherLite(SecretKey cek, byte[] iv, int cipherMode, Provider provider, boolean alwaysUseProvider,
                                              final CryptographicMaterials materials) {
        try {
            Cipher cipher = createCipher(provider, alwaysUseProvider, materials);
            cipher.init(cipherMode, cek, new IvParameterSpec(iv));
            return new GCMCipherLite(cipher, materials, cek, cipherMode, iv);
        } catch (GeneralSecurityException e) {
            throw new S3EncryptionClientException("Unable to build cipher: " + e.getMessage()
                            + "\nMake sure you have the JCE unlimited strength policy files installed and "
                            + "configured for your JVM.", e);
        }
    }

    /**
     * Create the cipher using the given provider. For now, we just use BouncyCastle.
     * TODO: Allow customers to configure their own crypto provider
     *
     * @param provider
     * @param alwaysUseProvider
     * @param materials
     * @return
     * @throws GeneralSecurityException
     */
    private static Cipher createCipher(Provider provider, boolean alwaysUseProvider, CryptographicMaterials materials)
            throws GeneralSecurityException {

        String algorithm = materials.algorithmSuite().cipherName();

        // TODO: Currently, we just always use bouncy castle. This is not compatible with the v1/v2 clients which have
        // a specific functionality that allows customers to prefer using a configured provider instead.
        // See createCipher @ L199 of ContentCryptoScheme.java in the v1 SDK for details.
        if (provider == null) {
            provider = Security.getProvider(PREFERRED_PROVIDER);
        }
        return Cipher.getInstance(algorithm, provider);
    }

    public static CipherLite createAuxiliaryCipher(SecretKey cek, byte[] ivOrig, int cipherMode,
                                                   Provider securityProvider, long startingBytePos, CryptographicMaterials materials) {
        byte[] iv = AesCtrUtils.adjustIV(ivOrig, startingBytePos);
        // TODO: This is actually supposed to be an AES-CTR cipherLite, not a GcmCipherLite
        return CipherLiteFactory.newGcmCipherLite(cek, iv, cipherMode, securityProvider, false, materials);
    }
}
