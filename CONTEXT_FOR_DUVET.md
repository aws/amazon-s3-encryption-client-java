# Duvet Annotation Context

## Overview
Working through incomplete Duvet requirements one at a time to add citations and tests to the codebase.

## Key Insights
- **Duvet syntax**: Only comments with exactly two slashes (`//`) are read by Duvet
  - `//=` for specification links
  - `//#` for requirement descriptions
  - `///` or `////` are NOT read by Duvet (effectively commented out)
- **Annotation types**: `type=implication`, `type=exception`, `type=test`
- **Report location**: `.duvet/reports/report.html`
- **Total requirements**: 198 (178 complete, 20 incomplete as of last run)

## Completed Requirements

### 1. V1 Format Exclusive Keys
**Requirement**: "When the object is encrypted using the V1 format, - Mapkeys exclusive to other format versions MUST NOT be present."

**Citation added**: 
- `MetadataKeyConstants.isV1Format()` at line 73
- `ContentMetadataDecodingStrategy.isV1InObjectMetadata()` at line 424

**Test**: Already tested via `ContentMetadataStrategyTest.testExclusiveKeysCollision`

### 2. V2 Format Tag Length Requirements
**Requirements**: 
- "If the object is encrypted using AES-GCM for content encryption, then the mapkey 'x-amz-tag-len' MUST be present."
- "If the object is encrypted using AES-CBC for content encryption, then the mapkey 'x-amz-tag-len' MUST NOT be present."

**Bug fixed**: Code was incorrectly writing tag length for CBC (should only be for GCM)

**Citation added**: `ContentMetadataEncodingStrategy.addMetadataToMap()` at line 190

**Implementation**: Check `cipherName().contains("GCM")` to determine whether to write tag length

**Test**: Existing tests validate tag length is written for GCM and read correctly

## Commit History
- `9068c876`: fix(CBC): Add annotations for V1/V2 format requirements and fix CBC tag length bug

## Files Modified
- `src/main/java/software/amazon/encryption/s3/internal/MetadataKeyConstants.java`
- `src/main/java/software/amazon/encryption/s3/internal/ContentMetadataEncodingStrategy.java`
- `src/main/java/software/amazon/encryption/s3/internal/ContentMetadataDecodingStrategy.java`

## Process for Next Requirements
1. User provides incomplete requirement text
2. Find where requirement is implemented in code
3. Add Duvet annotation at implementation location
4. Verify test coverage exists
5. Run tests: `mvn clean compile` then `mvn test -Dtest=ContentMetadataStrategyTest,MetadataKeyConstantsTest,CipherProviderTest,AlgorithmSuiteValidationTest`
6. Stage and commit changes

## Remaining Work
18 incomplete requirements remaining (as of last count)
