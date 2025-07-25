// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.internal;


import software.amazon.awssdk.awscore.AwsRequestOverrideConfiguration;
import software.amazon.awssdk.core.ApiName;

import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;
import java.util.Properties;
import java.util.function.Consumer;

/**
 * Provides the information for the ApiName APIs for the AWS SDK
 */
public class ApiNameVersion {
    private static final ApiName API_NAME = ApiNameVersion.apiNameWithVersion();
    // This is used in overrideConfiguration
    public static final Consumer<AwsRequestOverrideConfiguration.Builder> API_NAME_INTERCEPTOR =
            builder -> builder.addApiName(API_NAME);

    public static final String NAME = "AmazonS3Encrypt";
    public static final String API_VERSION_UNKNOWN = "3-unknown";

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
