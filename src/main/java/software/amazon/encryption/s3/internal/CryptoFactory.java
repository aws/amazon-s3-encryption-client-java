package software.amazon.encryption.s3.internal;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import software.amazon.encryption.s3.S3EncryptionClientException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

public class CryptoFactory {
    public static void checkACCP() {

        try {
            System.out.println(Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName());
            if (!Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName().equals(AmazonCorrettoCryptoProvider.PROVIDER_NAME)) {
                @SuppressWarnings("unchecked")
                Class<Provider> c = (Class<Provider>) Class.forName("com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider");
                Provider provider = c.newInstance();
                Security.addProvider(provider);
                if (Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName().equals(AmazonCorrettoCryptoProvider.PROVIDER_NAME)) {
                    System.out.println("Successfully Installed");
                } else {
                    System.out.println("Not installed");
                }
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InstantiationException | IllegalAccessException |
                 ClassNotFoundException e) {
            throw new S3EncryptionClientException(e.getMessage());
        }
    }

    public static Cipher createCipher(String algorithm, Provider provider)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        // if the user has specified a provider, go with that.
        if (provider != null) {
            return Cipher.getInstance(algorithm, provider);
        }

        // Otherwise, go with the default provider.
        return Cipher.getInstance(algorithm);
    }

    public  static KeyGenerator generateKey(String algorithm, Provider provider) {
        KeyGenerator generator;
        try {
            if (provider == null) {
                generator = KeyGenerator.getInstance(algorithm);
            } else {
                generator = KeyGenerator.getInstance(algorithm, provider);
            }
        }  catch (NoSuchAlgorithmException e) {
            throw new S3EncryptionClientException("Unable to generate a(n) " + algorithm + " data key", e);
        }
        return generator;
    }
}
