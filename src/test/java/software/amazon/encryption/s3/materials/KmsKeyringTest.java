// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.RetryingTest;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.encryption.s3.S3EncryptionClientException;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class KmsKeyringTest {

    private static final String KMS_KEY_ID = "arn:aws:kms:us-west-2:111122223333:key/example";

    @RetryingTest(3)
    public void buildKmsKeyringWithNullSecureRandomFails() {
        assertThrows(S3EncryptionClientException.class, () -> KmsKeyring.builder().secureRandom(null));
    }

    @RetryingTest(3)
    public void buildKmsKeyringWithNullDataKeyGeneratorFails() {
        assertThrows(S3EncryptionClientException.class, () -> KmsKeyring.builder().dataKeyGenerator(null));
    }

    // The data key was wrapped for a GCM object, so the KMS-authenticated encryption context carries
    // aws:x-amz-cek-alg = AES/GCM/NoPadding. The decryption materials select the CBC suite (as they would
    // if the content-algorithm metadata read CBC). The authenticated content algorithm and the selected
    // suite disagree, so onDecrypt must fail rather than return the data key.
    @Test
    public void kmsContextDecryptFailsWhenAuthenticatedCekAlgDoesNotMatchSelectedSuite() {
        Map<String, String> storedEncryptionContext = new HashMap<>();
        storedEncryptionContext.put("kms_cmk_id", KMS_KEY_ID);
        storedEncryptionContext.put("aws:x-amz-cek-alg", AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF.cipherName());

        // Releases the data key only for the encryption context it was wrapped under.
        KmsClient kmsClient = mock(KmsClient.class);
        when(kmsClient.decrypt(argThat((DecryptRequest request) ->
                storedEncryptionContext.equals(request.encryptionContext()))))
                .thenReturn(DecryptResponse.builder()
                        .keyId(KMS_KEY_ID)
                        .plaintext(SdkBytes.fromByteArray(new byte[32]))
                        .build());

        KmsKeyring keyring = KmsKeyring.builder()
                .kmsClient(kmsClient)
                .wrappingKeyId(KMS_KEY_ID)
                .build();

        DecryptionMaterials materials = DecryptionMaterials.builder()
                .s3Request(GetObjectRequest.builder().bucket("bucket").key("key").build())
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_CBC_IV16_NO_KDF)
                .encryptionContext(storedEncryptionContext)
                .build();

        EncryptedDataKey edk = EncryptedDataKey.builder()
                .keyProviderId(S3Keyring.KEY_PROVIDER_ID)
                .keyProviderInfo("kms+context")
                .encryptedDataKey(new byte[]{1, 2, 3})
                .build();

        assertThrows(S3EncryptionClientException.class,
                () -> keyring.onDecrypt(materials, Collections.singletonList(edk)));
    }

}
