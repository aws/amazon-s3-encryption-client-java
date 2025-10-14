// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests for the AesKeyMaterial and RsaKeyMaterial classes.
 */
public class KeyMaterialTest {

    /**
     * Test creating AesKeyMaterial using the builder.
     */
    @Test
    public void testAesKeyMaterial() throws NoSuchAlgorithmException {
        // Generate an AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        // Create a materials description
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create AesKeyMaterial using the builder
        AesKeyMaterial aesKeyMaterial = AesKeyMaterial.aesBuilder()
                .materialsDescription(materialsDescription)
                .keyMaterial(aesKey)
                .build();

        // Verify the key material
        assertEquals(materialsDescription, aesKeyMaterial.getMaterialsDescription());
        assertEquals(aesKey, aesKeyMaterial.getKeyMaterial());
    }

    /**
     * Test creating RsaKeyMaterial using the builder.
     */
    @Test
    public void testRsaKeyMaterial() throws NoSuchAlgorithmException {
        // Generate an RSA key pair
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair rsaKeyPair = keyPairGen.generateKeyPair();

        // Create a PartialRsaKeyPair
        PartialRsaKeyPair partialRsaKeyPair = PartialRsaKeyPair.builder()
                .publicKey(rsaKeyPair.getPublic())
                .privateKey(rsaKeyPair.getPrivate())
                .build();

        // Create a materials description
        MaterialsDescription materialsDescription = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();

        // Create RsaKeyMaterial using the builder
        RsaKeyMaterial rsaKeyMaterial = RsaKeyMaterial.rsaBuilder()
                .materialsDescription(materialsDescription)
                .keyMaterial(partialRsaKeyPair)
                .build();

        // Verify the key material
        assertEquals(materialsDescription, rsaKeyMaterial.getMaterialsDescription());
        assertEquals(partialRsaKeyPair, rsaKeyMaterial.getKeyMaterial());
    }

    /**
     * Test using AesKeyMaterial with additionalDecryptionKeyMaterial.
     */
    @Test
    public void testAesKeyMaterialWithAdditionalDecryptionKeyMaterial() throws NoSuchAlgorithmException {
        // Generate AES keys
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey1 = keyGen.generateKey();
        SecretKey aesKey2 = keyGen.generateKey();

        // Create materials descriptions
        MaterialsDescription materialsDescription1 = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();
        MaterialsDescription materialsDescription2 = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "2")
                .build();

        // Create a map with AesKeyMaterial
        Map<MaterialsDescription, RawKeyMaterial<SecretKey>> additionalKeyMaterial = new HashMap<>();

        // Old way (with explicit type parameters)
        additionalKeyMaterial.put(materialsDescription1, RawKeyMaterial.<SecretKey>builder()
                .materialsDescription(materialsDescription1)
                .keyMaterial(aesKey1)
                .build());

        // New way (with concrete type)
        additionalKeyMaterial.put(materialsDescription2, AesKeyMaterial.aesBuilder()
                .materialsDescription(materialsDescription2)
                .keyMaterial(aesKey2)
                .build());

        // Verify the map entries
        assertNotNull(additionalKeyMaterial.get(materialsDescription1));
        assertNotNull(additionalKeyMaterial.get(materialsDescription2));
        assertEquals(aesKey1, additionalKeyMaterial.get(materialsDescription1).getKeyMaterial());
        assertEquals(aesKey2, additionalKeyMaterial.get(materialsDescription2).getKeyMaterial());
    }

    /**
     * Test using RsaKeyMaterial with additionalDecryptionKeyMaterial.
     */
    @Test
    public void testRsaKeyMaterialWithAdditionalDecryptionKeyMaterial() throws NoSuchAlgorithmException {
        // Generate RSA key pairs
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair rsaKeyPair1 = keyPairGen.generateKeyPair();
        KeyPair rsaKeyPair2 = keyPairGen.generateKeyPair();

        // Create PartialRsaKeyPairs
        PartialRsaKeyPair partialRsaKeyPair1 = PartialRsaKeyPair.builder()
                .publicKey(rsaKeyPair1.getPublic())
                .privateKey(rsaKeyPair1.getPrivate())
                .build();
        PartialRsaKeyPair partialRsaKeyPair2 = PartialRsaKeyPair.builder()
                .publicKey(rsaKeyPair2.getPublic())
                .privateKey(rsaKeyPair2.getPrivate())
                .build();

        // Create materials descriptions
        MaterialsDescription materialsDescription1 = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "1")
                .build();
        MaterialsDescription materialsDescription2 = MaterialsDescription.builder()
                .put("purpose", "test")
                .put("version", "2")
                .build();

        // Create a map with RsaKeyMaterial
        Map<MaterialsDescription, RawKeyMaterial<PartialRsaKeyPair>> additionalKeyMaterial = new HashMap<>();

        // Old way (with explicit type parameters)
        additionalKeyMaterial.put(materialsDescription1, RawKeyMaterial.<PartialRsaKeyPair>builder()
                .materialsDescription(materialsDescription1)
                .keyMaterial(partialRsaKeyPair1)
                .build());

        // New way (with concrete type)
        additionalKeyMaterial.put(materialsDescription2, RsaKeyMaterial.rsaBuilder()
                .materialsDescription(materialsDescription2)
                .keyMaterial(partialRsaKeyPair2)
                .build());

        // Verify the map entries
        assertNotNull(additionalKeyMaterial.get(materialsDescription1));
        assertNotNull(additionalKeyMaterial.get(materialsDescription2));
        assertEquals(partialRsaKeyPair1, additionalKeyMaterial.get(materialsDescription1).getKeyMaterial());
        assertEquals(partialRsaKeyPair2, additionalKeyMaterial.get(materialsDescription2).getKeyMaterial());
    }
}
