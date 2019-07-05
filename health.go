package main

import (
	"errors"
	"net/http"
	"time"

	fthealth "github.com/Financial-Times/go-fthealth/v1_1"
	"github.com/Financial-Times/service-status-go/gtg"
)

type HealthService struct {
	repo *releaseRepository
}

func NewHealthService(repo *releaseRepository) *HealthService {
	return &HealthService{
		repo: repo,
	}
}

func (service *HealthService) HealthCheckHandler() func(w http.ResponseWriter, r *http.Request) {
	hc := fthealth.TimedHealthCheck{
		HealthCheck: fthealth.HealthCheck{
			SystemCode:  "coreos-version-checker",
			Name:        "CoreOS Version Checker",
			Description: "Checks for new CoreOS upgrades, and reports on the CVE severity score.",
			Checks:      service.checks(),
		},
		Timeout: 10 * time.Second,
	}
	return fthealth.Handler(hc)
}

func (service *HealthService) checks() []fthealth.Check {
	return []fthealth.Check{
		service.releaseInfoRetrievalCheck(),
		service.securityFixesCheck(),
		service.highSecurityFixesCheck(),
		service.criticalSecurityFixesCheck(),
		service.latestVersionCheck(),
	}
}

func (service *HealthService) releaseInfoRetrievalCheck() fthealth.Check {
	return fthealth.Check{
		BusinessImpact:   "No business impact.",
		Name:             "Error while checking CoreOS Release Versions",
		PanicGuide:       "https://dewey.ft.com/coreos-version-checker.html",
		Severity:         2,
		TechnicalSummary: "We were unable to retrieve data from CoreOS Release or the CVE Information APIs.",
		Checker:          errorRetrievingReleaseInfo(service.repo),
	}
}

func (service *HealthService) highSecurityFixesCheck() fthealth.Check {
	return fthealth.Check{
		BusinessImpact:   "It may be possible to compromise our publishing stack using a known security vulnerability.",
		Name:             "High Risk Security Fix Overdue",
		PanicGuide:       "https://dewey.ft.com/coreos-version-checker.html",
		Severity:         1,
		TechnicalSummary: "The latest version of CoreOS has a HIGH RISK security fix. The FT policy is to upgrade to this version within TWO WEEKS, a deadline which has now been passed!",
		Checker:          checkHighSecurityScore(service.repo),
	}
}

func (service *HealthService) criticalSecurityFixesCheck() fthealth.Check {
	return fthealth.Check{
		BusinessImpact:   "It may be possible to compromise our publishing stack using a known critical security vulnerability.",
		Name:             "Critical Security Fix",
		PanicGuide:       "https://dewey.ft.com/coreos-version-checker.html",
		Severity:         1,
		TechnicalSummary: "The latest version of CoreOS has a CRITICAL security fix.",
		Checker:          checkCriticalSecurityScore(service.repo),
	}
}

func (service *HealthService) securityFixesCheck() fthealth.Check {
	return fthealth.Check{
		BusinessImpact:   "It may be possible to compromise our publishing stack using a known security vulnerability.",
		Name:             "New CoreOS Version has Security Fixes",
		PanicGuide:       "https://dewey.ft.com/coreos-version-checker.html",
		Severity:         2,
		TechnicalSummary: "The latest version of CoreOS contains security fixes.",
		Checker:          checkAnySecurityFixes(service.repo),
	}
}

func (service *HealthService) latestVersionCheck() fthealth.Check {
	return fthealth.Check{
		BusinessImpact:   "No direct business impact, but there could be important bug fixes in the latest release.",
		Name:             "New CoreOS Version",
		PanicGuide:       "https://dewey.ft.com/coreos-version-checker.html",
		Severity:         2,
		TechnicalSummary: "The version of CoreOS doesn't match the latest available version from the official repository.",
		Checker:          compareInstalledWithLatest(service.repo),
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
		if err != nil && repo.latestVersion.MaxCVSS != nil && *repo.latestVersion.MaxCVSS >= 9 {
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
			*repo.latestVersion.MaxCVSS >= 7 &&
			repo.latestVersion.ReleaseDate != nil &&
			time.Now().After(repo.latestVersion.ReleaseDate.Add(time.Hour*336)) { // 336 hours = 2 weeks

			return "", errors.New("The new version has a HIGH LEVEL security fix that is over TWO WEEKS old! CoreOS must be upgraded.")
		}

		return "", nil
	}
}

func (service *HealthService) GTG() gtg.Status {
	var statusChecker []gtg.StatusChecker
	for _, c := range service.checks() {
		checkFunc := func() gtg.Status {
			return gtgCheck(c.Checker)
		}
		statusChecker = append(statusChecker, checkFunc)
	}
	return gtg.FailFastParallelCheck(statusChecker)()
}

func gtgCheck(handler func() (string, error)) gtg.Status {
	if _, err := handler(); err != nil {
		return gtg.Status{GoodToGo: false, Message: err.Error()}
	}
	return gtg.Status{GoodToGo: true}
}
