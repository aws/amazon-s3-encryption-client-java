package software.amazon.encryption.s3.materials;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class DefaultMaterialsManager {
    // TODO: allow this to be configurable?
    private final SecureRandom _secureRandom = new SecureRandom();
    private final Keyring _keyring;


    public DefaultMaterialsManager(Keyring keyring) {
        _keyring = keyring;
    }

    public EncryptionMaterials getEncryptionMaterials(EncryptionMaterialsRequest request) {
        SecretKey key = generateDataKey();

        EncryptionMaterials materials = EncryptionMaterials.builder()
                .algorithmSuiteId(0x0078)
                .encryptionContext(request.encryptionContext)
                .plaintextDataKey(key.getEncoded())
                .build();

        return _keyring.OnEncrypt(materials);
    }

    private SecretKey generateDataKey() {
        KeyGenerator generator;
        try {
            generator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Unable to generate an AES key", e);
        }

        generator.init(256 , _secureRandom);
        return generator.generateKey();
    }

    public static class EncryptionMaterialsRequest {
        public Map<String, String> encryptionContext;
    }
}
