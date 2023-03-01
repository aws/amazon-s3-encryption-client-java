# Changelog

## [2.2.0](https://github.com/aws/aws-s3-encryption-client-java/compare/v2.1.1...v2.2.0) (2023-03-01)


### Features

* Add S3CrtAsyncClient as MultipartPutobject ([#90](https://github.com/aws/aws-s3-encryption-client-java/issues/90)) ([24be141](https://github.com/aws/aws-s3-encryption-client-java/commit/24be14139937aa666ffa42a621cbe1bad72c7246))
* extend delegating client to enable non-encrypted API operations in default and async encrypion clients ([#94](https://github.com/aws/aws-s3-encryption-client-java/issues/94)) ([ba78c2c](https://github.com/aws/aws-s3-encryption-client-java/commit/ba78c2cd8d94be2f76614bc47bbf85a6e3f5c26e))


### Maintenance

* bump AWS SDK v2 deps and make S3 non-optional ([#93](https://github.com/aws/aws-s3-encryption-client-java/issues/93)) ([9d0c495](https://github.com/aws/aws-s3-encryption-client-java/commit/9d0c495c0cbb165b7d743b34eba191e26a95f07d))
* change algorithm suite IDs to match the specification ([#86](https://github.com/aws/aws-s3-encryption-client-java/issues/86)) ([322e88c](https://github.com/aws/aws-s3-encryption-client-java/commit/322e88c41270958f70594ad369239e782c6f56b6))
* cleanup some test code ([#92](https://github.com/aws/aws-s3-encryption-client-java/issues/92)) ([ba3be52](https://github.com/aws/aws-s3-encryption-client-java/commit/ba3be525a340930b20c7602de1aa71d57527ee7f))


### Fixes

* Revert "AWS S3 Encryption Client 1.0.1 Release -- $(date +%Y-%m-%d)" ([0d750cb](https://github.com/aws/aws-s3-encryption-client-java/commit/0d750cb47a811da0b61916814d121d8c36bfcbfb))
* Revert "AWS S3 Encryption Client 1.0.0 Release -- $(date +%Y-%m-%d)" ([80bc1fa](https://github.com/aws/aws-s3-encryption-client-java/commit/80bc1fabefb44503fae24ce27073f38884074d32))
* convert to a blocking input stream instead of going through a by… ([#96](https://github.com/aws/aws-s3-encryption-client-java/issues/96)) ([eea77c1](https://github.com/aws/aws-s3-encryption-client-java/commit/eea77c16c1a80b37e81a41f95250bca6c3ebf0c1))
* pass exception from doFinal to wrapped subscriber to avoid hanging ([#95](https://github.com/aws/aws-s3-encryption-client-java/issues/95)) ([7c64a9f](https://github.com/aws/aws-s3-encryption-client-java/commit/7c64a9fa27ae24abc7cf76ac63b610cc91998824))
* Remove default wrapped client ([#81](https://github.com/aws/aws-s3-encryption-client-java/issues/81)) ([287a63e](https://github.com/aws/aws-s3-encryption-client-java/commit/287a63e312b7c698d479d288aa0349a424763384))
* rename to Amazon S3 Encryption Client ([#89](https://github.com/aws/aws-s3-encryption-client-java/issues/89)) ([4950731](https://github.com/aws/aws-s3-encryption-client-java/commit/4950731a075f03cc51e8a7b29d6a444c80e51370))

### [2.1.1](https://github.com/aws/aws-s3-encryption-client-java/compare/v2.1.0...v2.1.1) (2023-02-21)


### Fixes

* export the release date to fix its interpolation ([809dabb](https://github.com/aws/aws-s3-encryption-client-java/commit/809dabbfd2ea714060bc51ab183b7cd61fb0b461))

## [2.1.0](https://github.com/aws/aws-s3-encryption-client-java/compare/v2.0.0...v2.1.0) (2023-02-21)


### Features

* not actually a feature, just a dummy commit to trigger a minor version bump ([ee5e90b](https://github.com/aws/aws-s3-encryption-client-java/commit/ee5e90beb12af80171b68bcbb39182c56b2847ea))


### Fixes

* update pom to 2.0.0 to match release tag ([9fe2509](https://github.com/aws/aws-s3-encryption-client-java/commit/9fe2509eb4c0aff2833b2ccd9bfaff655619cdb3))

## 1.0.0 (2023-02-20)


### Features

* Adds Async client, starting with DeleteObject(s) ([#54](https://github.com/aws/aws-s3-encryption-client-java/issues/54)) ([c7120e1](https://github.com/aws/aws-s3-encryption-client-java/commit/c7120e13931b842da5bdaf0de45f0ec2f4021792))
* Adds CBC stream decryption ([#25](https://github.com/aws/aws-s3-encryption-client-java/issues/25)) ([9970104](https://github.com/aws/aws-s3-encryption-client-java/commit/9970104cba3af9256d81157359ff22f1cb5b00eb))
* Configurable SecureRandom ([#40](https://github.com/aws/aws-s3-encryption-client-java/issues/40)) ([90cab2d](https://github.com/aws/aws-s3-encryption-client-java/commit/90cab2d9c9c6bf9dc9aa61d45e07372e2e386648))
* implement AES-GCM streaming ([#45](https://github.com/aws/aws-s3-encryption-client-java/issues/45)) ([d0bcd38](https://github.com/aws/aws-s3-encryption-client-java/commit/d0bcd38efb589d72f04f2aeae721de4a974718bd))
* implement CBC decryption in async getObject ([#59](https://github.com/aws/aws-s3-encryption-client-java/issues/59)) ([4fd2fa8](https://github.com/aws/aws-s3-encryption-client-java/commit/4fd2fa86d2e5a876293cbf5a15f8c6f01d456515))
* implement getObject async ([#56](https://github.com/aws/aws-s3-encryption-client-java/issues/56)) ([b9834ce](https://github.com/aws/aws-s3-encryption-client-java/commit/b9834ce85225d1392306bc05f4b734fd4fe8b544))
* implement putObject in Async client  ([#57](https://github.com/aws/aws-s3-encryption-client-java/issues/57)) ([f233d72](https://github.com/aws/aws-s3-encryption-client-java/commit/f233d720f324125e3087cbf407b23595fee0d651))
* Implement Ranged-Get ([#31](https://github.com/aws/aws-s3-encryption-client-java/issues/31)) ([65331fb](https://github.com/aws/aws-s3-encryption-client-java/commit/65331fbf96388b1f4149454a07621a828e33fe1d))
* Introduce delayed authentication ([#23](https://github.com/aws/aws-s3-encryption-client-java/issues/23)) ([b8eedac](https://github.com/aws/aws-s3-encryption-client-java/commit/b8eedacc3b7ffeac27aba5bc02fc79628e847e30))
* multi-part putObject ([#53](https://github.com/aws/aws-s3-encryption-client-java/issues/53)) ([281f383](https://github.com/aws/aws-s3-encryption-client-java/commit/281f383eda7f1352cac5fd4003474e295ba8aa32))
* Multipart Upload ([#43](https://github.com/aws/aws-s3-encryption-client-java/issues/43)) ([7e42811](https://github.com/aws/aws-s3-encryption-client-java/commit/7e428113b654a621bda0c5819647889627450028))


### Maintenance

* Create workflow to release S3EC to Github ([#52](https://github.com/aws/aws-s3-encryption-client-java/issues/52)) ([ef8effb](https://github.com/aws/aws-s3-encryption-client-java/commit/ef8effb4a1d5c2201fe5272f0f6191b0b3a71a8e))


### Fixes

* add instruction file support in getObject async ([#69](https://github.com/aws/aws-s3-encryption-client-java/issues/69)) ([ee61abd](https://github.com/aws/aws-s3-encryption-client-java/commit/ee61abddfa6422aa130ee4f681a604bd531b0f12))
* address some edge cases to fix async CBC ranged gets ([#70](https://github.com/aws/aws-s3-encryption-client-java/issues/70)) ([1da1cae](https://github.com/aws/aws-s3-encryption-client-java/commit/1da1caeee96e1abaae106942bbbae94169ccf19e))
* Guard against using another S3EC as wrappedClient ([#36](https://github.com/aws/aws-s3-encryption-client-java/issues/36)) ([30cf9b1](https://github.com/aws/aws-s3-encryption-client-java/commit/30cf9b15c43dd0b59e9cc1ff83729ec8c797c1d1))
