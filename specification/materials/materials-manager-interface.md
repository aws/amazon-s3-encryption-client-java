[//]: # "Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
[//]: # "SPDX-License-Identifier: CC-BY-SA-4.0"

# Materials Manager Interface (Addendum)

This is an addendum to the materials manager interface present in the AWS Encryption SDK, available [here](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md).
Only additional or changed information is specified here.

## Supported MMs

The Amazon S3 Encryption Client provides the following built-in MM types:

- [Default MM](default-mm.md)
- [Legacy Decrypt MM](./legacy/legacy-decrypt-mm.md)

Note: A user MAY create their own custom MM.
