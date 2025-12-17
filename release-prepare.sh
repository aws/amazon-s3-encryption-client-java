#!/bin/bash
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -e

VERSION=$1
MAJOR_VERSION=$(echo "$VERSION" | cut -d. -f1)

echo "Preparing release for version $VERSION (major: $MAJOR_VERSION)"

# Update Maven versions
mvn versions:set -DnewVersion="$VERSION" -DautoVersionSubmodules=true

# Portable sed for macOS and Linux
if [[ "$OSTYPE" == "darwin"* ]]; then
  SED_CMD="sed -i ''"
else
  SED_CMD="sed -i"
fi

# Update s3ec version in migration examples
$SED_CMD "s/<s3ec.version>.*<\/s3ec.version>/<s3ec.version>$VERSION<\/s3ec.version>/g" migration_examples/v3-to-v4/v4/pom.xml

# Update API_VERSION_UNKNOWN with major version
$SED_CMD "s/public static final String API_VERSION_UNKNOWN = \".*-unknown\"/public static final String API_VERSION_UNKNOWN = \"$MAJOR_VERSION-unknown\"/g" src/main/java/software/amazon/encryption/s3/internal/ApiNameVersion.java

# Update EXPECTED_API_MAJOR_VERSION
$SED_CMD "s/EXPECTED_API_MAJOR_VERSION = \"[0-9]*\"/EXPECTED_API_MAJOR_VERSION = \"$MAJOR_VERSION\"/g" src/test/java/software/amazon/encryption/s3/internal/ApiNameVersionTest.java

# Update version in README
$SED_CMD "s/<version>.*<\/version>/<version>$VERSION<\/version>/g" README.md

echo "Release preparation complete"