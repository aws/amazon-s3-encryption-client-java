// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;


import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.core.ApiName;

import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;
import java.util.Optional;
import java.util.Properties;

/**
 * Provides the information for the ApiName APIs for the AWS SDK
 */
public class ApiNameVersion {
    private static final ApiName API_NAME = ApiNameVersion.apiNameWithVersion();

    public static final String NAME = "AmazonS3Encrypt";
    public static final String API_VERSION_UNKNOWN = "4-unknown";

    /**
     * Returns an {@link AwsRequestOverrideConfiguration} which includes the S3EC API name while
     * preserving any override configuration the caller already set on their request. This ensures
     * caller-supplied configuration (e.g. custom headers, credentials providers, or signer
     * overrides) is not dropped when the S3EC adds its API name.
     *
     * @param existingOverrideConfiguration the override configuration from the original request, if any
     * @return an override configuration containing the S3EC API name merged with the existing configuration
     */
    public static AwsRequestOverrideConfiguration addApiNameToOverrideConfiguration(
            Optional<AwsRequestOverrideConfiguration> existingOverrideConfiguration) {
        return existingOverrideConfiguration
                .map(AwsRequestOverrideConfiguration::toBuilder)
                .orElseGet(AwsRequestOverrideConfiguration::builder)
                .addApiName(API_NAME)
                .build();
    }

    public static ApiName apiNameWithVersion() {
        return ApiName.builder()
                .name(NAME)
                .version(apiVersion())
                .build();
    }

    private static String apiVersion() {
        try {
            final Properties properties = new Properties();
            final ClassLoader loader = ApiNameVersion.class.getClassLoader();

            // Other JARs on the classpath may also define project.properties
            // Enumerate through and find the one for S3EC
            Enumeration<URL> urls = loader.getResources("project.properties");
            if (urls == null) {
                return API_VERSION_UNKNOWN;
            }
            while (urls.hasMoreElements()) {
                URL thisURL = urls.nextElement();
                if (thisURL.getPath().contains("amazon-s3-encryption-client-java")) {
                    properties.load(thisURL.openStream());
                    break;
                }
            }
            String maybeVersion = properties.getProperty("s3ecVersion");
            if (maybeVersion == null) {
                // This should never happen in practice,
                // but is included for robustness.
                return API_VERSION_UNKNOWN;
            } else {
                return maybeVersion;
            }
        } catch (final IOException ex) {
            return API_VERSION_UNKNOWN;
        }
    }
}
