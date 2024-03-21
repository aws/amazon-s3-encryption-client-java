# Changelog

## [3.1.2](https://github.com/aws/aws-s3-encryption-client-java/compare/v3.1.1...v3.1.2) (2024-03-21)


### Fixes

* create clients only if necessary ([#187](https://github.com/aws/aws-s3-encryption-client-java/issues/187)) ([ea0c0c7](https://github.com/aws/aws-s3-encryption-client-java/commit/ea0c0c762c6fd23204b0e59ae2a63b174880d48c))
* do not signal onComplete when the incoming buffer length is less than the cipher block ([#209](https://github.com/aws/aws-s3-encryption-client-java/issues/209)) ([8b1a686](https://github.com/aws/aws-s3-encryption-client-java/commit/8b1a686e8ed5aae867dfc96b1b7a4b5e2ddeb095))


### Maintenance

* fix dependabot.yml ([#190](https://github.com/aws/aws-s3-encryption-client-java/issues/190)) ([5ee8b08](https://github.com/aws/aws-s3-encryption-client-java/commit/5ee8b08fea7efaa25e8f6b0914134a0bb8bc5c9b))
* modify range to allow queries specifying only the start index ([#184](https://github.com/aws/aws-s3-encryption-client-java/issues/184)) ([765b9c6](https://github.com/aws/aws-s3-encryption-client-java/commit/765b9c6a8ee61800fb98db30d64e5832f4cc6e39))
* **README:** detail no unencrypted pass through ([#189](https://github.com/aws/aws-s3-encryption-client-java/issues/189)) ([576ea66](https://github.com/aws/aws-s3-encryption-client-java/commit/576ea661f5e6b098fad41999022b80c2a30f72dc)), closes [#186](https://github.com/aws/aws-s3-encryption-client-java/issues/186) [/github.com/aws/amazon-s3-encryption-client-java/issues/186#issuecomment-1973016669](https://github.com/aws//github.com/aws/amazon-s3-encryption-client-java/issues/186/issues/issuecomment-1973016669)

## [3.1.1](https://github.com/aws/aws-s3-encryption-client-java/compare/v3.1.0...v3.1.1) (2024-01-24)


### Fixes

* Close threads when calling PutObject ([#180](https://github.com/aws/aws-s3-encryption-client-java/issues/180)) ([45b69fb](https://github.com/aws/aws-s3-encryption-client-java/commit/45b69fb1f2716f6cf2d114e1b6383670607580a1))


### Maintenance

* allow ToolsDevelopment to Assume CI Role ([#179](https://github.com/aws/aws-s3-encryption-client-java/issues/179)) ([a9fdaa3](https://github.com/aws/aws-s3-encryption-client-java/commit/a9fdaa38ee826902e360fa6db1415e7e44705f99))
* fix release script ([#177](https://github.com/aws/aws-s3-encryption-client-java/issues/177)) ([60c377b](https://github.com/aws/aws-s3-encryption-client-java/commit/60c377b88adf27dda2803f6dfe7c4b493d0f80d8))
* update artifact-hunt.yml to pick the version from pom.xml ([#176](https://github.com/aws/aws-s3-encryption-client-java/issues/176)) ([9f6b90f](https://github.com/aws/aws-s3-encryption-client-java/commit/9f6b90fd8b486ffae0109c32b5308563808d6531))
* update node version in version step ([#181](https://github.com/aws/aws-s3-encryption-client-java/issues/181)) ([49c2069](https://github.com/aws/aws-s3-encryption-client-java/commit/49c2069cd2a190035604d4450ea9d863175e713f))

## [3.1.0](https://github.com/aws/aws-s3-encryption-client-java/compare/v3.0.1...v3.1.0) (2023-08-31)


### Features

* add configuration option to set max buffer size ([#166](https://github.com/aws/aws-s3-encryption-client-java/issues/166)) ([ecf6e6c](https://github.com/aws/aws-s3-encryption-client-java/commit/ecf6e6c0f9e03ce0e4c4333d60118651e495aea2))
* multipart & ranged get examples ([#168](https://github.com/aws/aws-s3-encryption-client-java/issues/168)) ([203e5dc](https://github.com/aws/aws-s3-encryption-client-java/commit/203e5dc89f4ed5f264def37521755395f9b25990))
* Refactor `KmsKeyring` to use `GenerateDataKey` instead of `Encrypt` ([#171](https://github.com/aws/aws-s3-encryption-client-java/issues/171)) ([a1a22a4](https://github.com/aws/aws-s3-encryption-client-java/commit/a1a22a49a912565642b6c561a05b97390c326e1a))


### Fixes

* Create default wrapped clients only if necessary. ([#163](https://github.com/aws/aws-s3-encryption-client-java/issues/163)) ([285eab6](https://github.com/aws/aws-s3-encryption-client-java/commit/285eab68fdc2468e678d3b745d6502a9584752e4))
* unwrap completion exception in AbortMultipartUpload and inside multipart putObject ([#174](https://github.com/aws/aws-s3-encryption-client-java/issues/174)) ([84baad8](https://github.com/aws/aws-s3-encryption-client-java/commit/84baad81bafb23b6690a1000447e1433da79ae6d))


### Maintenance

* allow CI to run in forks ([#164](https://github.com/aws/aws-s3-encryption-client-java/issues/164)) ([66a5ca4](https://github.com/aws/aws-s3-encryption-client-java/commit/66a5ca4ceb670bf5d598baa92a96668694bee3b6))
* **deps-dev:** bump bcprov-jdk18on from 1.72 to 1.74 ([#169](https://github.com/aws/aws-s3-encryption-client-java/issues/169)) ([5502eab](https://github.com/aws/aws-s3-encryption-client-java/commit/5502eab44d272dbc94ce7aa94ecb9a050f699c3a))
* fix bugs and nit ([#175](https://github.com/aws/aws-s3-encryption-client-java/issues/175)) ([926818b](https://github.com/aws/aws-s3-encryption-client-java/commit/926818b0febbf823839a5053b6d9d5a25352faab))
* install dependabot ([#172](https://github.com/aws/aws-s3-encryption-client-java/issues/172)) ([1c63fdb](https://github.com/aws/aws-s3-encryption-client-java/commit/1c63fdb87d3cb95caf0b496e148c145a26ea08f9))
* warn against use of Encryption Context for non-kms keyrings. ([#173](https://github.com/aws/aws-s3-encryption-client-java/issues/173)) ([54557a9](https://github.com/aws/aws-s3-encryption-client-java/commit/54557a9660ce16e80dc58cd4f842a26b59c133b7))

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
