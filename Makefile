# Used for misc supporting functions like Duvet and prettier. Builds, tests, etc. should use the usual Java/Maven tooling.

duvet: | duvet_extract duvet_report

duvet_extract:
	rm -rf compliance
	$(foreach file, $(shell find specification/s3-encryption -name '*.md'), duvet extract -o compliance -f MARKDOWN $(file);)

duvet_report:
	duvet \
		report \
		--spec-pattern "compliance/**/*.toml" \
		--source-pattern "src/**/*.java" \
		--html specification_compliance_report.html
