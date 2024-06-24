// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.utils;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.CompletableFuture;

/**
 * Determines which AWS resources to use while running tests.
 */
public class S3EncryptionClientTestResources {

    public static final AwsCredentialsProvider CREDENTIALS = DefaultCredentialsProvider.create();
    public static final SdkHttpClient HTTP_CLIENT = ApacheHttpClient.create();
    public static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");
    public static final String KMS_KEY_ID = System.getenv("AWS_S3EC_TEST_KMS_KEY_ID");
    // This alias must point to the same key as KMS_KEY_ID
    public static final String KMS_KEY_ALIAS = System.getenv("AWS_S3EC_TEST_KMS_KEY_ALIAS");
    public static final Region KMS_REGION = Region.of(System.getenv("AWS_REGION"));

    /**
     * For a given string, append a suffix to distinguish it from
     * simultaneous test runs.
     * @param s
     * @return
     */
    public static String appendTestSuffix(final String s) {
        StringBuilder stringBuilder = new StringBuilder(s);
        stringBuilder.append(DateTimeFormat.forPattern("-yyMMdd-hhmmss-").print(new DateTime()));
        stringBuilder.append((int) (Math.random() * 100000));
        return stringBuilder.toString();
    }

    /**
     * Delete the object for the given objectKey in the given bucket.
     * @param bucket the bucket to delete the object from
     * @param objectKey the key of the object to delete
     */
    public static void deleteObject(final String bucket, final String objectKey, final S3Client s3Client) {
        s3Client.deleteObject(builder -> builder
                .bucket(bucket)
                .key(objectKey)
                .build());
    }

    /**
     * Delete the object for the given objectKey in the given bucket.
     * @param bucket the bucket to delete the object from
     * @param objectKey the key of the object to delete
     */
    public static void deleteObject(final String bucket, final String objectKey, final S3AsyncClient s3Client) {
        CompletableFuture<DeleteObjectResponse> response = s3Client.deleteObject(builder -> builder
                .bucket(bucket)
                .key(objectKey));
        // Ensure completion before return
        response.join();
    }


    /**
     * @return If an RSA KeyPair already exists in Test Resources, load and return that.<p>
     * Otherwise, generate a new key pair, persist that to Resources, and return it.<p>
     * Assumes working directory is root of the git repo.
     */
    public static KeyPair getRSAKeyPair() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path resourceDirectory = Paths.get("src","test","resources");
        if (resourceDirectory.resolve("RSAPrivateKey.pem").toFile().exists() && resourceDirectory.resolve("RSAPublicKey.pem").toFile().exists()) {
            return readKeyPairFromTestResourcesFile(resourceDirectory);
        }
        KeyPair keyPair = generateKeyPair(2048);
        writeKeyPairToTestResourcesFile(keyPair, resourceDirectory);
        return keyPair;
    }

    public static KeyPair generateKeyPair(final int keySize) {
        if (!(keySize == 2048 || keySize == 4096)) throw new IllegalArgumentException("Only 2048 or 4096 are valid key sizes.");
        KeyPairGenerator rsaGen;
        try {
            rsaGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No such algorithm", e);
        }
        rsaGen.initialize(keySize, new SecureRandom());
        return rsaGen.generateKeyPair();
    }

    private static void writePEMFile(Key key, String description, Path filePath) throws IOException {
        final PemObject pemObject = new PemObject(description, key.getEncoded());
        try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(Files.newOutputStream(filePath)))) {
            pemWriter.writeObject(pemObject);
        }
    }

    private static PemObject readPEMFile(Path filePath) throws IOException {
        try (PemReader pemReader = new PemReader(new InputStreamReader(Files.newInputStream(filePath)))) {
            return pemReader.readPemObject();
        }
    }

    private static void writeKeyPairToTestResourcesFile(final KeyPair keyPair, Path resourceDirectory) throws IOException {
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        writePEMFile(privateKey, "RSA PRIVATE KEY", resourceDirectory.resolve("RSAPrivateKey.pem"));
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        writePEMFile(publicKey, "RSA PUBLIC KEY", resourceDirectory.resolve("RSAPublicKey.pem"));
    }

    private static KeyPair readKeyPairFromTestResourcesFile(Path resourceDirectory) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final KeyFactory factory = KeyFactory.getInstance("RSA");
        byte[] privateKeyContent = readPEMFile(resourceDirectory.resolve("RSAPrivateKey.pem")).getContent();
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyContent);
        final PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
        byte[] publicKeyContent = readPEMFile(resourceDirectory.resolve("RSAPublicKey.pem")).getContent();
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyContent);
        final PublicKey publicKey = factory.generatePublic(publicKeySpec);
        return new KeyPair(publicKey, privateKey);
    }
}
