package software.amazon.encryption.s3.internal;


import software.amazon.awssdk.core.ApiName;

import java.io.IOException;
import java.util.Properties;

/**
 * Provides the information for the ApiName APIs for the AWS SDK
 */
public class ApiNameVersion {
    public static final String API_NAME = "AmazonS3Encrypt";

    public static final String API_VERSION_UNKNOWN = "3-unknown";

    public static ApiName apiNameWithVersion() {
        return ApiName.builder()
                .name(API_NAME)
                .version(apiVersion())
                .build();
    }

    private static String apiVersion() {
        try {
            final Properties properties = new Properties();
            final ClassLoader loader = ApiNameVersion.class.getClassLoader();
            properties.load(loader.getResourceAsStream("project.properties"));
            return properties.getProperty("version");
        } catch (final IOException ex) {
            return API_VERSION_UNKNOWN;
        }
    }
}
