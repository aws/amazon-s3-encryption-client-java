package software.amazon.encryption.s3.internal;

import software.amazon.awssdk.core.ApiName;

/**
 * Provides the information for the ApiName APIs for the AWS SDK
 */
public class ApiNameVersion {
    public static final String API_NAME = "AwsS3Encrypt";

    public static final String API_VERSION_UNKNOWN = "unknown";

    public static ApiName apiNameWithVersion() {
        return ApiName.builder()
                .name(API_NAME)
                .version(apiVersion())
                .build();
    }

    private static String apiVersion() {
        // TODO: Use a resources file akin to ESDK to populate this
        return API_VERSION_UNKNOWN;
    }
}
