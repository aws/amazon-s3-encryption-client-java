package software.amazon.encryption.s3;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.encryption.s3.materials.CryptographicMaterialsManager;
import software.amazon.encryption.s3.materials.Keyring;
import software.amazon.encryption.s3.materials.PartialRsaKeyPair;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.Provider;
import java.security.SecureRandom;

public class S3ClientBuilder {
    S3Client _wrappedClient = S3Client.builder().build();

    S3AsyncClient _wrappedAsyncClient = S3AsyncClient.builder().build();

    CryptographicMaterialsManager _cryptoMaterialsManager;
    Keyring _keyring;
    SecretKey _aesKey;
    PartialRsaKeyPair _rsaKeyPair;
    String _kmsKeyId;
    boolean _enableLegacyUnauthenticatedModes = false;
    boolean _enableDelayedAuthenticationMode = false;
    boolean _enableMultipartPutObject = false;
    Provider _cryptoProvider = null;
    SecureRandom _secureRandom = new SecureRandom();

    S3ClientBuilder() {
    }

    /**
     * Note that this does NOT create a defensive clone of S3Client. Any modifications made to the wrapped
     * S3Client will be reflected in this Builder.
     */
    @SuppressFBWarnings(value = "EI_EXPOSE_REP2", justification = "Pass mutability into wrapping client")
    public S3ClientBuilder wrappedClient(S3Client wrappedClient) {
        if (wrappedClient instanceof S3EncryptionClient) {
            throw new S3EncryptionClientException("Cannot use S3EncryptionClient as wrapped client");
        }

        this._wrappedClient = wrappedClient;
        return this;
    }

    public S3ClientBuilder cryptoMaterialsManager(CryptographicMaterialsManager cryptoMaterialsManager) {
        this._cryptoMaterialsManager = cryptoMaterialsManager;
        checkKeyOptions();

        return this;
    }

    public S3ClientBuilder keyring(Keyring keyring) {
        this._keyring = keyring;
        checkKeyOptions();

        return this;
    }

    public S3ClientBuilder aesKey(SecretKey aesKey) {
        this._aesKey = aesKey;
        checkKeyOptions();

        return this;
    }

    public S3ClientBuilder rsaKeyPair(KeyPair rsaKeyPair) {
        this._rsaKeyPair = new PartialRsaKeyPair(rsaKeyPair);
        checkKeyOptions();

        return this;
    }

    public S3ClientBuilder rsaKeyPair(PartialRsaKeyPair partialRsaKeyPair) {
        this._rsaKeyPair = partialRsaKeyPair;
        checkKeyOptions();

        return this;
    }

    public S3ClientBuilder kmsKeyId(String kmsKeyId) {
        this._kmsKeyId = kmsKeyId;
        checkKeyOptions();

        return this;
    }

    // We only want one way to use a key, if more than one is set, throw an error
    private void checkKeyOptions() {
        if (S3EncryptionClientUtilities.onlyOneNonNull(_cryptoMaterialsManager, _keyring, _aesKey, _rsaKeyPair, _kmsKeyId)) {
            return;
        }

        throw new S3EncryptionClientException("Only one may be set of: crypto materials manager, keyring, AES key, RSA key pair, KMS key id");
    }

    public S3ClientBuilder enableLegacyUnauthenticatedModes(boolean shouldEnableLegacyUnauthenticatedModes) {
        this._enableLegacyUnauthenticatedModes = shouldEnableLegacyUnauthenticatedModes;
        return this;
    }

    public S3ClientBuilder enableDelayedAuthenticationMode(boolean shouldEnableDelayedAuthenticationMode) {
        this._enableDelayedAuthenticationMode = shouldEnableDelayedAuthenticationMode;
        return this;
    }

    public S3ClientBuilder enableMultipartPutObject(boolean _enableMultipartPutObject) {
        this._enableMultipartPutObject = _enableMultipartPutObject;
        return this;
    }

    public S3ClientBuilder cryptoProvider(Provider cryptoProvider) {
        this._cryptoProvider = cryptoProvider;
        return this;
    }

    public S3ClientBuilder secureRandom(SecureRandom secureRandom) {
        if (secureRandom == null) {
            throw new S3EncryptionClientException("SecureRandom provided to S3EncryptionClient cannot be null");
        }
        _secureRandom = secureRandom;
        return this;
    }

    public <T>T build() {
        throw new UnsupportedOperationException();
    }
}
