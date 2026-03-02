// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.BeforeAll;
import org.junitpioneer.jupiter.RetryingTest;
import software.amazon.encryption.s3.S3EncryptionClientException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

public class PartialRsaKeyPairTest {

    private static final String KEY_ALGORITHM = "RSA";
    private static KeyPair RSA_KEY_PAIR;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = java.security.KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(2048);
        RSA_KEY_PAIR = keyPairGen.generateKeyPair();
    }

    @RetryingTest(3)
    public void testGetPublicKey() {
        PartialRsaKeyPair partialRsaKeyPair = new PartialRsaKeyPair(null, RSA_KEY_PAIR.getPublic());

        assertEquals(RSA_KEY_PAIR.getPublic(), partialRsaKeyPair.getPublicKey());
        assertThrows(S3EncryptionClientException.class, partialRsaKeyPair::getPrivateKey);
        assertEquals(KEY_ALGORITHM, partialRsaKeyPair.getPublicKey().getAlgorithm());
    }

    @RetryingTest(3)
    public void testGetPrivateKey() {
        PartialRsaKeyPair partialRsaKeyPair = new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), null);

        assertEquals(RSA_KEY_PAIR.getPrivate(), partialRsaKeyPair.getPrivateKey());
        assertThrows(S3EncryptionClientException.class, partialRsaKeyPair::getPublicKey);
        assertEquals(KEY_ALGORITHM, partialRsaKeyPair.getPrivateKey().getAlgorithm());
    }

    @RetryingTest(3)
    public void testBothKeysNull() {
        assertThrows(S3EncryptionClientException.class, () -> new PartialRsaKeyPair(null, null));
    }

    @RetryingTest(3)
    public void testBuilder() {
        PartialRsaKeyPair expectedKeyPair = new PartialRsaKeyPair(RSA_KEY_PAIR);

        PartialRsaKeyPair actualKeyPair = PartialRsaKeyPair.builder()
                .publicKey(RSA_KEY_PAIR.getPublic())
                .privateKey(RSA_KEY_PAIR.getPrivate())
                .build();

        assertEquals(expectedKeyPair, actualKeyPair);
    }

    @RetryingTest(3)
    public void testInequality() {
        PartialRsaKeyPair firstKeyPair = new PartialRsaKeyPair(RSA_KEY_PAIR);
        PartialRsaKeyPair onlyPublicKeyPair = new PartialRsaKeyPair(null, RSA_KEY_PAIR.getPublic());
        PartialRsaKeyPair onlyPrivateKeyPair = new PartialRsaKeyPair(RSA_KEY_PAIR.getPrivate(), null);

        assertNotEquals(null, firstKeyPair);
        assertNotEquals(firstKeyPair, onlyPublicKeyPair);
        assertNotEquals(firstKeyPair, onlyPrivateKeyPair);
        assertNotEquals(onlyPrivateKeyPair, onlyPublicKeyPair);
    }

    @RetryingTest(3)
    public void testHashCodeSameKeyPair() {
        PartialRsaKeyPair firstKeyPair = new PartialRsaKeyPair(RSA_KEY_PAIR);
        PartialRsaKeyPair secondKeyPair = new PartialRsaKeyPair(RSA_KEY_PAIR);

        assertEquals(firstKeyPair.hashCode(), secondKeyPair.hashCode());
    }

    @RetryingTest(3)
    public void testHashCodeDifferentKeyPair() {
        PartialRsaKeyPair firstKeyPair = new PartialRsaKeyPair(RSA_KEY_PAIR);
        PartialRsaKeyPair secondKeyPair = new PartialRsaKeyPair(null, RSA_KEY_PAIR.getPublic());

        assertNotEquals(firstKeyPair.hashCode(), secondKeyPair.hashCode());
    }
}
