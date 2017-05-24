package main

import (
	"errors"
	"net/http"
	"time"

	fthealth "github.com/Financial-Times/go-fthealth/v1a"
)

// Health returns a handler for the standard FT healthchecks
func Health(repo *releaseRepository) func(w http.ResponseWriter, r *http.Request) {
	return fthealth.Handler("coreos-version-checker", "Checks for new CoreOS upgrades, and reports on the CVE severity score.", getHealthchecks(repo)...)
}

func getHealthchecks(repo *releaseRepository) []fthealth.Check {
	return []fthealth.Check{
		{
			BusinessImpact:   "No direct business impact, but there could be important bug fixes in the latest release.",
			Name:             "New CoreOS Version",
			PanicGuide:       "https://dewey.ft.com/coreos-version-checker.html",
			Severity:         2,
			TechnicalSummary: "The version of CoreOS doesn't match the latest available version from the official repository.",
			Checker:          compareInstalledWithLatest(repo),
		},
		{
			BusinessImpact:   "It may be possible to compromise our publishing stack using a known security vulnerability.",
			Name:             "New CoreOS Version has Security Fixes",
			PanicGuide:       "https://dewey.ft.com/coreos-version-checker.html",
			Severity:         2,
			TechnicalSummary: "The latest version of CoreOS contains security fixes.",
			Checker:          checkAnySecurityFixes(repo),
		},
		{
			BusinessImpact:   "It may be possible to compromise our publishing stack using a known critical security vulnerability.",
			Name:             "Critical Security Fix",
			PanicGuide:       "https://dewey.ft.com/coreos-version-checker.html",
			Severity:         1,
			TechnicalSummary: "The latest version of CoreOS has a CRITICAL security fix.",
			Checker:          checkCriticalSecurityScore(repo),
		},
		{
			BusinessImpact:   "It may be possible to compromise our publishing stack using a known security vulnerability.",
			Name:             "High Risk Security Fix Overdue",
			PanicGuide:       "https://dewey.ft.com/coreos-version-checker.html",
			Severity:         1,
			TechnicalSummary: "The latest version of CoreOS has a HIGH RISK security fix. The FT policy is to upgrade to this version within TWO WEEKS, a deadline which has now been passed!",
			Checker:          checkHighSecurityScore(repo),
		},
		{
			BusinessImpact:   "No business impact.",
			Name:             "Error while checking CoreOS Release Versions",
			PanicGuide:       "https://dewey.ft.com/coreos-version-checker.html",
			Severity:         2,
			TechnicalSummary: "We were unable to retrieve data from CoreOS Release or the CVE Information APIs.",
			Checker:          errorRetrievingReleaseInfo(repo),
		},
	}
}

func compareInstalledWithLatest(repo *releaseRepository) func() (string, error) {
	return func() (string, error) {
		repo.RLock()
		defer repo.RUnlock()

		if repo.installedVersion.Version != repo.latestVersion.Version {
			return "", errors.New("There is a new version of CoreOS available: " + repo.latestVersion.Version)
		}

		return "", nil
	}
}

func errorRetrievingReleaseInfo(repo *releaseRepository) func() (string, error) {
	return func() (string, error) {
		repo.RLock()
		defer repo.RUnlock()

		return "", repo.err
	}
}

func checkCriticalSecurityScore(repo *releaseRepository) func() (string, error) {
	return func() (string, error) {
		repo.RLock()
		defer repo.RUnlock()

		_, err := compareInstalledWithLatest(repo)()
		if err != nil && *repo.latestVersion.MaxCVSS > 9 {
			return "", errors.New("The new version has a CRITICAL security fix! CoreOS must be upgraded within TWO DAYS!")
		}

		return "", nil
	}
}

func checkAnySecurityFixes(repo *releaseRepository) func() (string, error) {
	return func() (string, error) {
		repo.RLock()
		defer repo.RUnlock()

		_, err := compareInstalledWithLatest(repo)()
		if err != nil && repo.latestVersion.MaxCVSS != nil && *repo.latestVersion.MaxCVSS > 0 {
			return "", errors.New("The new version has at least one security fix, and should be prioritised for upgrade.")
		}

		return "", nil
	}
}

func checkHighSecurityScore(repo *releaseRepository) func() (string, error) {
	return func() (string, error) {
		repo.RLock()
		defer repo.RUnlock()

		_, err := compareInstalledWithLatest(repo)()
		if err != nil &&
			repo.latestVersion.MaxCVSS != nil &&
			*repo.latestVersion.MaxCVSS > 7 &&
			repo.latestVersion.ReleasedOn != nil &&
			time.Now().After(repo.latestVersion.ReleasedOn.Add(time.Hour*336)) { // 336 hours = 2 weeks

			return "", errors.New("The new version has a HIGH LEVEL security fix that is over TWO WEEKS old! CoreOS must be upgraded.")
		}

		return "", nil
	}
}
