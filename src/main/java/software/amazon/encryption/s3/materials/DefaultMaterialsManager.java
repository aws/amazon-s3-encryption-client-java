package software.amazon.encryption.s3.materials;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

public class DefaultMaterialsManager implements MaterialsManager {
    // TODO: allow this to be configurable?
    private final SecureRandom _secureRandom = new SecureRandom();
    private final Keyring _keyring;


    public DefaultMaterialsManager(Keyring keyring) {
        _keyring = keyring;
    }

    public EncryptionMaterials getEncryptionMaterials(EncryptionMaterialsRequest request) {
        SecretKey key = generateDataKey();

        EncryptionMaterials materials = EncryptionMaterials.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_NO_KDF)
                .encryptionContext(request.encryptionContext)
                .plaintextDataKey(key.getEncoded())
                .build();

        return _keyring.onEncrypt(materials);
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

    public DecryptionMaterials getDecryptionMaterials(DecryptionMaterialsRequest request) {
        DecryptionMaterials materials = DecryptionMaterials.builder()
                .algorithmSuite(request.algorithmSuite)
                .encryptionContext(request.encryptionContext)
                .build();

        return _keyring.onDecrypt(materials, request.encryptedDataKeys);
    }

}
