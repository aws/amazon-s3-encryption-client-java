# Changelog

### [3.0.1](https://github.com/aws/aws-s3-encryption-client-java/compare/v3.0.0...v3.0.1) (2023-06-01)


### Maintenance

* add metadata downgrade tests([#55](https://github.com/aws/aws-s3-encryption-client-java/issues/55)) ([0fed900](https://github.com/aws/aws-s3-encryption-client-java/commit/0fed9007b6370552421bd1b3bcbba7f3789be47f))
* fix some issues with release ([#156](https://github.com/aws/aws-s3-encryption-client-java/issues/156)) ([c6b4e64](https://github.com/aws/aws-s3-encryption-client-java/commit/c6b4e644b29c36adfedf3190cf2a139d8a130cda))


### Fixes

* null check for InputStream in ApiNameVersion ([#161](https://github.com/aws/aws-s3-encryption-client-java/issues/161)) ([c23aeb2](https://github.com/aws/aws-s3-encryption-client-java/commit/c23aeb2dc7d33e54b7f285dba9691412675d0a02))
* unwrap CompletionException in default client, rethrow as S3Encry… ([#162](https://github.com/aws/aws-s3-encryption-client-java/issues/162)) ([1a00d3e](https://github.com/aws/aws-s3-encryption-client-java/commit/1a00d3e9046cb0902d0f19249ec79a6a85b85cf5))

## [3.0.0](https://github.com/aws/aws-s3-encryption-client-java/compare/v2.0.0...v3.0.0) (2023-04-06)


### ⚠ BREAKING CHANGES

* prod release for S3 EC (#152)

### Features

* prod release for S3 EC ([#152](https://github.com/aws/aws-s3-encryption-client-java/issues/152)) ([d724eab](https://github.com/aws/aws-s3-encryption-client-java/commit/d724eab8b5c090c5ea8e1a7e299fab0273fbe08b))


### Fixes

* Revert "Amazon S3 Encryption Client 2.0.1 Release -- $(date +%Y-%m-%d)" (#151) ([a62e455](https://github.com/aws/aws-s3-encryption-client-java/commit/a62e4552c2b41bded2820c9a7fb60fd789667ec2)), closes [#151](https://github.com/aws/aws-s3-encryption-client-java/issues/151)
* remove illegal javadoc syntax ([#147](https://github.com/aws/aws-s3-encryption-client-java/issues/147)) ([412a02c](https://github.com/aws/aws-s3-encryption-client-java/commit/412a02c8b096b586e21d459c7850af1cfc826652))
* remove illegal javadoc tags ([#148](https://github.com/aws/aws-s3-encryption-client-java/issues/148)) ([d5682b9](https://github.com/aws/aws-s3-encryption-client-java/commit/d5682b9e2b3e17deb2c25af071652e323cc139f5))


### Maintenance

* add scm url to pom.xml ([#155](https://github.com/aws/aws-s3-encryption-client-java/issues/155)) ([22ac9ad](https://github.com/aws/aws-s3-encryption-client-java/commit/22ac9ad056452a45b0d032954ab7d1da6a0f55fa))
* add the developer guide to the README ([#150](https://github.com/aws/aws-s3-encryption-client-java/issues/150)) ([b41a07b](https://github.com/aws/aws-s3-encryption-client-java/commit/b41a07b873bf4479a816bc3de7fd2f443e877c94))
* point release at correct internal staging domain, fix group id ([#149](https://github.com/aws/aws-s3-encryption-client-java/issues/149)) ([f88e89d](https://github.com/aws/aws-s3-encryption-client-java/commit/f88e89da9c7a8547715a1e675239e0291094514a))
