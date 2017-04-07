package main

import fthealth "github.com/Financial-Times/go-fthealth/v1a"

func (v versionChecker) Checks() []fthealth.Check {
	versionCh = make(chan result)
	go loop(latest, 300, versionCh)
	check := fthealth.Check{
		BusinessImpact: "It may be possible to compromise our publishing stack using a known security vulnerability.",
		Name:           "CoreOS version",
		PanicGuide: `* Visit https://coreos.com/releases/ and look at the release notes for the latest version.
* Check whether any Security Fixes have been included.
* For each security fix, check its CVSS score.
* If any security fix has a CVSS score higher than 7, then this is a Critical Update.
* Any updates which aren't critical can be acknowledged out-of-hours and an email sent to the Universal Publishing team.
* Critical Updates should be escalated to Technical Operations.
* Technical Operations should attempt to upgrade CoreOS in the pre-prod environment.  See https://github.com/Financial-Times/coreos-upgrade/wiki for instructions.
* If the pre-prod upgrade is successful, the same should be applied to production.
* If either upgrade fails, Tech Ops should escalate to 3rd line support.`,
		Severity:         1,
		TechnicalSummary: "The version of CoreOS doesn't match the latest available version from the official repository.",
		Checker:          v.Check,
	}
	return []fthealth.Check{check}
}
