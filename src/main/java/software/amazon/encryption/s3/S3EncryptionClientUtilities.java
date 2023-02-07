package software.amazon.encryption.s3;

import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.encryption.s3.materials.AesKeyring;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.DefaultCryptoMaterialsManager;
import software.amazon.encryption.s3.materials.Keyring;
import software.amazon.encryption.s3.materials.KmsKeyring;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;
import software.amazon.encryption.s3.materials.RsaKeyring;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.List;
import java.util.stream.Collectors;

/**
 * This class contains that which can be shared between the default S3 Encryption
 * Client and its Async counterpart.
 * TODO: move encryption context handling here
 * TODO: move the builder here
 */
public class S3EncryptionClientUtilities {

    public static final String INSTRUCTION_FILE_SUFFIX = ".instruction";

    /**
     * For a given DeleteObjectsRequest, return a list of ObjectIdentifiers
     * representing the corresponding instruction files to delete.
     * @param request a DeleteObjectsRequest
     * @return the list of ObjectIdentifiers for instruction files to delete
     */
    static List<ObjectIdentifier> instructionFileKeysToDelete(final DeleteObjectsRequest request) {
        return request.delete().objects().stream()
                .map(o -> o.toBuilder().key(o.key() + INSTRUCTION_FILE_SUFFIX).build())
                .collect(Collectors.toList());
    }

    static boolean onlyOneNonNull(Object... values) {
        boolean haveOneNonNull = false;
        for (Object o : values) {
            if (o != null) {
                if (haveOneNonNull) {
                    return false;
                }

                haveOneNonNull = true;
            }
        }

        return haveOneNonNull;
    }

    static CryptographicMaterialsManager buildCMM(S3ClientBuilder builder) {
        if (!onlyOneNonNull(builder._cryptoMaterialsManager, builder._keyring, builder._aesKey, builder._rsaKeyPair, builder._kmsKeyId)) {
            throw new S3EncryptionClientException("Exactly one must be set of: crypto materials manager, keyring, AES key, RSA key pair, KMS key id");
        }

        if (builder._keyring == null) {
            if (builder._aesKey != null) {
                builder._keyring = AesKeyring.builder()
                        .wrappingKey(builder._aesKey)
                        .enableLegacyUnauthenticatedModes(builder._enableLegacyUnauthenticatedModes)
                        .secureRandom(builder._secureRandom)
                        .build();
            } else if (builder._rsaKeyPair != null) {
                builder._keyring = RsaKeyring.builder()
                        .wrappingKeyPair(builder._rsaKeyPair)
                        .enableLegacyUnauthenticatedModes(builder._enableLegacyUnauthenticatedModes)
                        .secureRandom(builder._secureRandom)
                        .build();
            } else if (builder._kmsKeyId != null) {
                builder._keyring = KmsKeyring.builder()
                        .wrappingKeyId(builder._kmsKeyId)
                        .enableLegacyUnauthenticatedModes(builder._enableLegacyUnauthenticatedModes)
                        .secureRandom(builder._secureRandom)
                        .build();
            }
        }

        if (builder._cryptoMaterialsManager == null) {
            builder._cryptoMaterialsManager = DefaultCryptoMaterialsManager.builder()
                    .keyring(builder._keyring)
                    .cryptoProvider(builder._cryptoProvider)
                    .build();
        }

        return builder._cryptoMaterialsManager;
    }
}
