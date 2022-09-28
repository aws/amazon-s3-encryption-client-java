package software.amazon.encryption.s3;

import com.amazonaws.services.s3.AmazonS3EncryptionClientV2;
import com.amazonaws.services.s3.AmazonS3EncryptionV2;
import com.amazonaws.services.s3.model.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.async.AsyncRequestBody;
import software.amazon.awssdk.core.async.AsyncResponseTransformer;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;
import software.amazon.awssdk.utils.IoUtils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.encryption.s3.S3EncryptionClient.withAdditionalEncryptionContext;

/**
 * This class is an integration test for verifying compatibility of S3 Async Client across different keys.
 */
public class S3AsyncEncryptionClientCompatibilityTest {

    private static final String BUCKET = System.getenv("AWS_S3EC_TEST_BUCKET");
    private static final String KMS_KEY_ID = System.getenv("AWS_S3EC_TEST_KMS_KEY_ID");

    private static SecretKey AES_KEY;
    private static KeyPair RSA_KEY_PAIR;

    @BeforeAll
    public static void setUp() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        AES_KEY = keyGen.generateKey();

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        RSA_KEY_PAIR = keyPairGen.generateKeyPair();
    }

    @Test
    void s3AsyncTest() throws ExecutionException, InterruptedException {
        final String BUCKET_KEY = "s3-async-test";
        final String input = "S3Async";
        S3AsyncClient v3AsyncClient = S3AsyncClient.builder().build();

        CompletableFuture<PutObjectResponse> putResponseFuture =
                v3AsyncClient.putObject(PutObjectRequest.builder()
                                .bucket(BUCKET)
                                .key(BUCKET_KEY)
                                .build(),
                        AsyncRequestBody.fromString(input));
        putResponseFuture.join();

        CompletableFuture<ResponseBytes<GetObjectResponse>> getResponseFuture =
                v3AsyncClient.getObject(GetObjectRequest.builder()
                                .bucket(BUCKET)
                                .key(BUCKET_KEY)
                                .build(),
                        AsyncResponseTransformer.toBytes());
        getResponseFuture.join();

        String output = getResponseFuture.get().asUtf8String();
        assertEquals(input, output);
        v3AsyncClient.close();
    }

    @Test
    void s3AsyncFileTest() throws ExecutionException, InterruptedException, IOException {
        final String BUCKET_KEY = "s3-async-test-file";
        S3AsyncClient v3AsyncClient = S3AsyncClient.builder().build();

        File inputFile = new File("src/test/java/software/amazon/encryption/s3/dummyImage.jpg");
        File outputFile = new File("src/test/java/software/amazon/encryption/s3/AesAsyncV3toV3File.jpg");
        CompletableFuture<PutObjectResponse> putResponseFuture =
                v3AsyncClient.putObject(PutObjectRequest.builder()
                                .bucket(BUCKET)
                                .key(BUCKET_KEY)
                                .build(),
                        AsyncRequestBody.fromFile(inputFile));
        putResponseFuture.join();

        CompletableFuture<GetObjectResponse> getResponseFuture =
                v3AsyncClient.getObject(GetObjectRequest.builder()
                                .bucket(BUCKET)
                                .key(BUCKET_KEY)
                                .build(),
                        AsyncResponseTransformer.toFile(outputFile));
        getResponseFuture.join();

        //byte[] output = getResponseFuture.get().asByteArray();
        byte[] input1 = IoUtils.toByteArray(RequestBody.fromFile(inputFile).contentStreamProvider().newStream());
        byte[] output = IoUtils.toByteArray(RequestBody.fromFile(outputFile).contentStreamProvider().newStream());
        assertEquals(Arrays.toString(input1), Arrays.toString(output));
        v3AsyncClient.close();
    }

    @Test
    public void AesAsyncV3toV3File() throws ExecutionException, InterruptedException, IOException {
        final String BUCKET_KEY = "Awesome";

        // Async V3 Client
        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        File inputFile = new File("src/test/java/software/amazon/encryption/s3/dummyImage.jpg");
        File outputFile = new File("src/test/java/software/amazon/encryption/s3/AesAsyncV3toV3File.jpg");
        CompletableFuture<PutObjectResponse> putResponseFuture = v3AsyncClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), AsyncRequestBody.fromFile(inputFile));

        putResponseFuture.join();

        CompletableFuture<GetObjectResponse> getResponseFuture = v3AsyncClient.getObject(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), AsyncResponseTransformer.toFile(outputFile));
        getResponseFuture.join();
//        // Asserts
        assertEquals(Arrays.toString(IoUtils.toByteArray(RequestBody.fromFile(inputFile).contentStreamProvider().newStream())),
                Arrays.toString(IoUtils.toByteArray(RequestBody.fromFile(outputFile).contentStreamProvider().newStream())));
        v3AsyncClient.close();
    }


    @Test
    public void AesAsyncV3toV3() throws ExecutionException, InterruptedException {
        final String BUCKET_KEY = "aes-async-v3-to-v3";

        // Async V3 Client
        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        final String input = "AesAsyncV3toV3";

        CompletableFuture<PutObjectResponse> putResponseFuture = v3AsyncClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), AsyncRequestBody.fromString(input));
        putResponseFuture.join();

        CompletableFuture<ResponseBytes<GetObjectResponse>> getResponseFuture = v3AsyncClient.getObject(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), AsyncResponseTransformer.toBytes());
        getResponseFuture.join();
        // Asserts
        final String output = getResponseFuture.get().asUtf8String();
        assertEquals(input, output);
        v3AsyncClient.close();
    }

    @Test
    public void RsaAsyncV3toV3() throws ExecutionException, InterruptedException {
        final String BUCKET_KEY = "rsa-async-v3-to-v3";

        // Async V3 Client
        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .rsaKeyPair(RSA_KEY_PAIR)
                .build();

        final String input = "RsaAsyncV3toV3";

        CompletableFuture<PutObjectResponse> putResponseFuture = v3AsyncClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), AsyncRequestBody.fromString(input));
        putResponseFuture.join();

        CompletableFuture<ResponseBytes<GetObjectResponse>> getResponseFuture = v3AsyncClient.getObject(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), AsyncResponseTransformer.toBytes());
        getResponseFuture.join();
        // Asserts
        final String output = getResponseFuture.get().asUtf8String();
        assertEquals(input, output);
        v3AsyncClient.close();
    }

    @Test
    public void KmsContextAsyncV3toV3() throws ExecutionException, InterruptedException {
        final String BUCKET_KEY = "kms-async-v3-to-v3";

        // Async V3 Client
        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        final String input = "KmsContextAsyncV3toV3";

        CompletableFuture<PutObjectResponse> putResponseFuture = v3AsyncClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), AsyncRequestBody.fromString(input));
        putResponseFuture.join();

        CompletableFuture<ResponseBytes<GetObjectResponse>> getResponseFuture = v3AsyncClient.getObject(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), AsyncResponseTransformer.toBytes());
        getResponseFuture.join();
        // Asserts
        final String output = getResponseFuture.get().asUtf8String();
        assertEquals(input, output);
        v3AsyncClient.close();
    }

    @Test
    public void AesGcmAsyncV2toV3WithInstructionFile() throws ExecutionException, InterruptedException {
        final String BUCKET_KEY = "aes-gcm-async-v2-to-v3-with-instruction-file";

        // V2 Client
        EncryptionMaterialsProvider materialsProvider =
                new StaticEncryptionMaterialsProvider(new EncryptionMaterials(AES_KEY));
        CryptoConfigurationV2 cryptoConfig =
                new CryptoConfigurationV2(CryptoMode.StrictAuthenticatedEncryption)
                        .withStorageMode(CryptoStorageMode.InstructionFile);
        AmazonS3EncryptionV2 v2Client = AmazonS3EncryptionClientV2.encryptionBuilder()
                .withCryptoConfiguration(cryptoConfig)
                .withEncryptionMaterialsProvider(materialsProvider)
                .build();

        // Async V3 Client
        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .aesKey(AES_KEY)
                .build();

        // Asserts
        final String input = "AesGcmAsyncV2toV3";
        v2Client.putObject(BUCKET, BUCKET_KEY, input);

        CompletableFuture<ResponseBytes<GetObjectResponse>> getResponseFuture = v3AsyncClient.getObject(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), AsyncResponseTransformer.toBytes());
        getResponseFuture.join();
        String output = getResponseFuture.get().asUtf8String();
        assertEquals(input, output);
        v3AsyncClient.close();
    }

    @Test
    public void KmsContextAsyncUpload() throws ExecutionException, InterruptedException, IOException {
        final String BUCKET_KEY = "kms-async-upload-sync-download";

        // Async V3 Client
        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        File inputFile = new File("src/test/java/software/amazon/encryption/s3/dummyImage.jpg");//.withCannedAcl(CannedAccessControlList.PublicRead);
        File outputFile = new File("src/test/java/software/amazon/encryption/s3/KmsContextAsyncUpload.jpg");
        CompletableFuture<PutObjectResponse> putResponseFuture = v3AsyncClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), AsyncRequestBody.fromFile(inputFile));
        putResponseFuture.join();

        S3Client v3Client = S3EncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .enableLegacyModes(true)
                .build();

        GetObjectResponse objectResponse = v3Client.getObject(builder -> builder
                .bucket(BUCKET)
                .key(BUCKET_KEY), ResponseTransformer.toFile(outputFile));
                //.overrideConfiguration(withAdditionalEncryptionContext(encryptionContext)));
        // Asserts
        
        assertEquals(Arrays.toString(IoUtils.toByteArray(RequestBody.fromFile(inputFile).contentStreamProvider().newStream())),
                Arrays.toString(IoUtils.toByteArray(RequestBody.fromFile(outputFile).contentStreamProvider().newStream())));
        v3AsyncClient.close();
    }

    @Test
    public void KmsContextAsyncFile() throws ExecutionException, InterruptedException, IOException {
        final String BUCKET_KEY = "kms-async";

        // Async V3 Client
        S3AsyncClient v3AsyncClient = S3AsyncEncryptionClient.builder()
                .kmsKeyId(KMS_KEY_ID)
                .build();

        File inputFile = new File("src/test/java/software/amazon/encryption/s3/dummyImage.jpg");//.withCannedAcl(CannedAccessControlList.PublicRead);
        File outputFile = new File("src/test/java/software/amazon/encryption/s3/KmsContextAsyncFile.jpg");
        CompletableFuture<PutObjectResponse> putResponseFuture = v3AsyncClient.putObject(PutObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), AsyncRequestBody.fromFile(inputFile));
        putResponseFuture.join();

        CompletableFuture<GetObjectResponse> getResponseFuture = v3AsyncClient.getObject(GetObjectRequest.builder()
                .bucket(BUCKET)
                .key(BUCKET_KEY)
                .build(), AsyncResponseTransformer.toFile(outputFile));
        getResponseFuture.join();

        assertEquals(Arrays.toString(IoUtils.toByteArray(RequestBody.fromFile(inputFile).contentStreamProvider().newStream())),
                Arrays.toString(IoUtils.toByteArray(RequestBody.fromFile(outputFile).contentStreamProvider().newStream())));
        v3AsyncClient.close();
    }


}
