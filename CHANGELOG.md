# Changelog

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
