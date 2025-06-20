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
  protected final boolean _reEncryptInstructionFile;

  protected RawKeyring(Builder<?, ?> builder) {
    super(builder);
    _materialsDescription = builder._materialsDescription;
    _reEncryptInstructionFile = builder._reEncryptInstructionFile;
  }
  public MaterialsDescription getMaterialsDescription() {
    return _materialsDescription;
  }
  public boolean getReEncryptInstructionFile() {
    return _reEncryptInstructionFile;
  }
  public EncryptionMaterials modifyMaterialHelper(EncryptionMaterials materials) {
    warnIfEncryptionContextIsPresent(materials);
    if (_materialsDescription != null && !_materialsDescription.isEmpty()) {
      materials = materials.toBuilder()
        .materialsDescription(_materialsDescription)
        .build();
      return materials;
    }

    return materials;
  }
  public void warnIfEncryptionContextIsPresent(EncryptionMaterials materials) {
    materials.s3Request().overrideConfiguration()
      .flatMap(overrideConfiguration ->
        overrideConfiguration.executionAttributes()
          .getOptionalAttribute(S3EncryptionClient.ENCRYPTION_CONTEXT))
      .ifPresent(ctx -> LogFactory.getLog(getClass()).warn("Usage of Encryption Context provides no security benefit in " + getClass().getSimpleName()));
  }
  public static abstract class Builder<KeyringT extends RawKeyring, BuilderT extends Builder<KeyringT, BuilderT>>
      extends S3Keyring.Builder<KeyringT, BuilderT> {

    protected MaterialsDescription _materialsDescription;
    protected boolean _reEncryptInstructionFile = false;

    protected Builder() {
      super();
    }

    public BuilderT materialsDescription(MaterialsDescription materialsDescription) {
      _materialsDescription = materialsDescription;
      return builder();
    }

    public BuilderT reEncryptInstructionFile(boolean reEncryptInstructionFile) {
      _reEncryptInstructionFile = reEncryptInstructionFile;
      return builder();
    }
  }
}
