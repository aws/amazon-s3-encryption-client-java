# Used for misc supporting functions like Duvet and prettier. Builds, tests, etc. should use the usual Java/Maven tooling.

duvet: | duvet_clean duvet_report

duvet_report:
	duvet report

duvet-view-report-mac:
	open .duvet/reports/report.html

duvet_clean:
	rm -rf .duvet/reports/ .duvet/requirements/
