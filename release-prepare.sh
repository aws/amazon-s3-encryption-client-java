#!/bin/bash
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -e

VERSION=$1
MAJOR_VERSION=$(echo "$VERSION" | cut -d. -f1)

echo "Preparing release for version $VERSION (major: $MAJOR_VERSION)"

mvn versions:set -DnewVersion="$VERSION" -DautoVersionSubmodules=true

# Portable sed for macOS and Linux
SED="sed -i"
[[ "$OSTYPE" == "darwin"* ]] && SED="sed -i ''"

$SED "s/<s3ec.version>.*<\/s3ec.version>/<s3ec.version>$VERSION<\/s3ec.version>/g" migration_examples/v3-to-v4/v4/pom.xml
$SED "s/API_VERSION_UNKNOWN = \".*-unknown\"/API_VERSION_UNKNOWN = \"$MAJOR_VERSION-unknown\"/g" src/main/java/software/amazon/encryption/s3/internal/ApiNameVersion.java
$SED "s/EXPECTED_API_MAJOR_VERSION = \"[0-9]*\"/EXPECTED_API_MAJOR_VERSION = \"$MAJOR_VERSION\"/g" src/test/java/software/amazon/encryption/s3/internal/ApiNameVersionTest.java
$SED "s/<version>.*<\/version>/<version>$VERSION<\/version>/g" README.md

echo "Release preparation complete"
