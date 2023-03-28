# Changelog

## [2.6.0](https://github.com/aws/aws-s3-encryption-client-java/compare/v2.5.0...v2.6.0) (2023-03-28)


### Features

* add missing legacy v1 RSA key wrap mode ([#127](https://github.com/aws/aws-s3-encryption-client-java/issues/127)) ([0173678](https://github.com/aws/aws-s3-encryption-client-java/commit/017367825be0f3874a6b445887bb493704acd8f6))


### Fixes

* handle v1 CBC with kms wrapping mode ([#126](https://github.com/aws/aws-s3-encryption-client-java/issues/126)) ([7ec170d](https://github.com/aws/aws-s3-encryption-client-java/commit/7ec170dea0cc027f4f8e93dccc0a0a82251eec72))
* update uploadPart request to use correct contentLength ([#124](https://github.com/aws/aws-s3-encryption-client-java/issues/124)) ([b2dbf22](https://github.com/aws/aws-s3-encryption-client-java/commit/b2dbf2289afc92fd2551b7bfcb06afb9d011733d))


### Maintenance

* change repo name in remaining locations ([#128](https://github.com/aws/aws-s3-encryption-client-java/issues/128)) ([74ed42e](https://github.com/aws/aws-s3-encryption-client-java/commit/74ed42ed2a3226532b6d6a3c89cd1009343c0e5b))

## [2.5.0](https://github.com/aws/aws-s3-encryption-client-java/compare/v2.4.1...v2.5.0) (2023-03-23)


### Features

* makes the default wrapped client configurable through the builder ([#122](https://github.com/aws/aws-s3-encryption-client-java/issues/122)) ([41d8471](https://github.com/aws/aws-s3-encryption-client-java/commit/41d8471ba5680ebf34ed813507bed427cb995e24))


### Maintenance

* properly cleanup after tests ([#120](https://github.com/aws/aws-s3-encryption-client-java/issues/120)) ([51ec36d](https://github.com/aws/aws-s3-encryption-client-java/commit/51ec36d30591b2e4db41449e57879910f7261ba7))


### Fixes

* cast ByteBuffer to Buffer for Java 8 compatibility ([#123](https://github.com/aws/aws-s3-encryption-client-java/issues/123)) ([f7fab26](https://github.com/aws/aws-s3-encryption-client-java/commit/f7fab26a7517b372d326018d63c558fcc23d8df9))
* move to isLastPart parameter in uploadPart and fix its usage ([#119](https://github.com/aws/aws-s3-encryption-client-java/issues/119)) ([6470fb8](https://github.com/aws/aws-s3-encryption-client-java/commit/6470fb87126d252f698bc8e6e92f8b693ed3d26b))

### [2.4.1](https://github.com/aws/aws-s3-encryption-client-java/compare/v2.4.0...v2.4.1) (2023-03-21)


### Fixes

* validate partContentLength against request/request body in uploa… ([#115](https://github.com/aws/aws-s3-encryption-client-java/issues/115)) ([0215807](https://github.com/aws/aws-s3-encryption-client-java/commit/0215807796f3947b90b28ad495e2ef0eb85fcf6b))

## [2.4.0](https://github.com/aws/aws-s3-encryption-client-java/compare/v2.3.0...v2.4.0) (2023-03-20)


### Features

* implement retries in (Buffered)CipherSubscriber ([#109](https://github.com/aws/aws-s3-encryption-client-java/issues/109)) ([12dd80c](https://github.com/aws/aws-s3-encryption-client-java/commit/12dd80cf18e7f6c8f94f245e234ee19acd2f6e32))
* multipart putObject async ([#114](https://github.com/aws/aws-s3-encryption-client-java/issues/114)) ([b985a4e](https://github.com/aws/aws-s3-encryption-client-java/commit/b985a4e18135943e11104bcbdaca836aaed5603e))


### Maintenance

* clean up some dead code and resolved TODOs ([#108](https://github.com/aws/aws-s3-encryption-client-java/issues/108)) ([72f75d0](https://github.com/aws/aws-s3-encryption-client-java/commit/72f75d0dd1acc1fa2063e5135a377bd303002acd))


### Fixes

* also close the default wrapped client ([#117](https://github.com/aws/aws-s3-encryption-client-java/issues/117)) ([7700fbb](https://github.com/aws/aws-s3-encryption-client-java/commit/7700fbb938757972b34d32a98f29503d4b170e0d))
* set release version to Java 8 to ensure bytecode compatibility a… ([#111](https://github.com/aws/aws-s3-encryption-client-java/issues/111)) ([1886895](https://github.com/aws/aws-s3-encryption-client-java/commit/188689516b3583500352bc6ceed3eb5588a23bf6))
* wrap the NoSuchKeyException when decrypting plaintext ([#116](https://github.com/aws/aws-s3-encryption-client-java/issues/116)) ([8d89adf](https://github.com/aws/aws-s3-encryption-client-java/commit/8d89adff421df65a9db77340bfd8aa5b47bf67fc))

## [2.3.0](https://github.com/aws/aws-s3-encryption-client-java/compare/v2.2.0...v2.3.0) (2023-03-13)


### Features

* implement BufferedCipherSubscriber to enforce buffered decrypti… ([#99](https://github.com/aws/aws-s3-encryption-client-java/issues/99)) ([87411c8](https://github.com/aws/aws-s3-encryption-client-java/commit/87411c83d43761ec8548d77287585cca99b8aeaa))


### Maintenance

* add a new test class for ranged gets using the CRT client ([#104](https://github.com/aws/aws-s3-encryption-client-java/issues/104)) ([9b244be](https://github.com/aws/aws-s3-encryption-client-java/commit/9b244be7a40527e69942ace7137cb0898eb8411f))


### Fixes

* handle contentLength in request object ([#106](https://github.com/aws/aws-s3-encryption-client-java/issues/106)) ([58ee9bc](https://github.com/aws/aws-s3-encryption-client-java/commit/58ee9bc1e97ff52854edd2f6e0c28a3f7e31e38a))
* regression in ranged gets when using buffered subscriber ([#107](https://github.com/aws/aws-s3-encryption-client-java/issues/107)) ([ebcddbf](https://github.com/aws/aws-s3-encryption-client-java/commit/ebcddbf4a0fdd2c1c3327f50119d4dec009abf97))
* remove duplicate call to appendTestPrefix in deleteObjects ([#97](https://github.com/aws/aws-s3-encryption-client-java/issues/97)) ([62953a6](https://github.com/aws/aws-s3-encryption-client-java/commit/62953a667112c18e5575ecb483d779d6fb4f1a6e))
* Revert "feat: Add S3CrtAsyncClient as MultipartPutobject ([#90](https://github.com/aws/aws-s3-encryption-client-java/issues/90))" ([#103](https://github.com/aws/aws-s3-encryption-client-java/issues/103)) ([93011f2](https://github.com/aws/aws-s3-encryption-client-java/commit/93011f253d23cd5e953f00fd5130e57021293313))
* update README to reflect option split ([#105](https://github.com/aws/aws-s3-encryption-client-java/issues/105)) ([5efabf8](https://github.com/aws/aws-s3-encryption-client-java/commit/5efabf8624c836676fc8e0859c0941925b91a700))

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
