// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.encryption.s3.materials;

import org.apache.commons.logging.LogFactory;
import software.amazon.encryption.s3.S3EncryptionClient;

/**
 * This is an abstract base class for keyrings that use raw cryptographic keys (AES + RSA)
 */
public abstract class RawKeyring extends S3Keyring {
  protected final MaterialsDescription _materialsDescription;

  protected RawKeyring(Builder<?, ?> builder) {
    super(builder);
    _materialsDescription = builder._materialsDescription;
  }

  public EncryptionMaterials modifyMaterialsForRawKeyring(EncryptionMaterials materials) {
    warnIfEncryptionContextIsPresent(materials);
    if (_materialsDescription != null && !_materialsDescription.isEmpty()) {
      materials = materials.toBuilder()
        .materialsDescription(_materialsDescription)
        .build();
    }
    return materials;
  }

  /**
   * Checks if an encryption context is present in the EncryptionMaterials and issues a warning
   * if an encryption context is found.
   * <p>
   * Encryption context is not recommended for use with
   * non-KMS keyrings as it does not provide additional security benefits and is not stored.
   *
   * @param materials EncryptionMaterials
   */

  public void warnIfEncryptionContextIsPresent(EncryptionMaterials materials) {
    materials.s3Request().overrideConfiguration()
      .flatMap(overrideConfiguration ->
        overrideConfiguration.executionAttributes()
          .getOptionalAttribute(S3EncryptionClient.ENCRYPTION_CONTEXT))
      .ifPresent(ctx -> LogFactory.getLog(getClass()).warn("Usage of Encryption Context provides no " +
        "security benefit in " + getClass().getSimpleName() + ".Additionally, this Encryption Context WILL NOT be " +
        "stored in the material description. Provide a MaterialDescription in the Keyring's builder instead."));
  }

  public static abstract class Builder<KeyringT extends RawKeyring, BuilderT extends Builder<KeyringT, BuilderT>>
      extends S3Keyring.Builder<KeyringT, BuilderT> {

    protected MaterialsDescription _materialsDescription;

    protected Builder() {
      super();
    }

    public BuilderT materialsDescription(MaterialsDescription materialsDescription) {
      _materialsDescription = materialsDescription;
      return builder();
    }
  }
}
