// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.encryption.s3.algorithms.AlgorithmSuite;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

public class ContentMetadataStrategyTest {

    private S3Client mockS3client;
    private Map<String, String> metadata = new HashMap<>();
    private GetObjectResponse getObjectResponse;
    private ContentMetadata expectedContentMetadata;
    private GetObjectRequest getObjectRequest;

    @BeforeEach
    public void setUp() {
        mockS3client = mock(S3Client.class);
        metadata.put("x-amz-tag-len" , "128");
        metadata.put("x-amz-wrap-alg" , "AES/GCM");
        metadata.put("x-amz-cek-alg" , "AES/GCM/NoPadding");
        metadata.put("x-amz-key-v2" , "dYHaV24t2HuNACA50fWTh2xpMDk+kpnfhHBcaEonAR3kte6WTmV9uOUxFgyVpz+2dAcJQDj6AKrxKElf");
        metadata.put("x-amz-iv" , "j3GWQ0HQVDOkPDf+");
        metadata.put("x-amz-matdesc" , "{}");
        getObjectRequest = GetObjectRequest.builder()
                .bucket("TestBucket")
                .key("TestKey")
                .build();
    }

    @Test
    public void decodeWithObjectMetadata() {
        getObjectResponse = GetObjectResponse.builder()
                .metadata(metadata)
                .build();
        byte[] bytes = {-113, 113, -106, 67, 65, -48, 84, 51, -92, 60, 55, -2};
        expectedContentMetadata = ContentMetadata.builder()
                .algorithmSuite(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                .encryptedDataKeyAlgorithm(null)
                .encryptedDataKeyContext(new HashMap())
                .contentIv(bytes)
                .build();

        ContentMetadata contentMetadata = ContentMetadataStrategy.decode(getObjectRequest, getObjectResponse);
        assertEquals(expectedContentMetadata.algorithmSuite(), contentMetadata.algorithmSuite());
        String actualContentIv = Arrays.toString(contentMetadata.contentIv());
        String expectedContentIv = Arrays.toString(expectedContentMetadata.contentIv());
        assertEquals(expectedContentIv, actualContentIv);
    }
}