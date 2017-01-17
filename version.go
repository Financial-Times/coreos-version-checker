package main

import (
	"errors"
	"fmt"
	fthealth "github.com/Financial-Times/go-fthealth/v1a"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	versionUri string = "http://%s.release.core-os.net/amd64-usr/current/version.txt"
)

var versionCh chan result

type versionChecker struct{}

func (v versionChecker) Checks() []fthealth.Check {
	versionCh = make(chan result)
	go loop(latest, 300, versionCh)
	check := fthealth.Check{
		BusinessImpact:   "It may be possible to compromise our publishing stack using a known security vulnerability.",
		Name:             "CoreOS version",
		PanicGuide:       `* Visit https://coreos.com/releases/ and look at the release notes for the latest version.
* Check whether any Security Fixes have been included.
* For each security fix, check its CVSS score.
* If any security fix has a CVSS score higher than 7, then this is a Critical Update.
* Any updates which aren't critical can be acknowledged out-of-hours and an email sent to the Universal Publishing team.
* Critical Updates should be escalated to Technical Operations.
* Technical Operations should attempt to upgrade CoreOS in the pre-prod environment.  See https://github.com/Financial-Times/coreos-upgrade/wiki for instructions.
* If the pre-prod upgrade is successful, the same should be applied to production.
* If either upgrade fails, Tech Ops should escalate to 3rd line support.`,
		Severity:         1,
		TechnicalSummary: "The version of CoreOS doesn't match the latest available version from the offical repository.",
		Checker:          v.Check,
	}
	return []fthealth.Check{check}
}

func (v versionChecker) Check() (string, error) {
	result := <-versionCh
	return result.val, result.err
}

func latest() result {
	channel, err := valFromFile("GROUP=", *hostPath+"/etc/coreos/update.conf")
	if err != nil {
		return result{err: err}
	}
	release, err := valFromFile("COREOS_RELEASE_VERSION=", *hostPath+"/usr/share/coreos/release")
	if err != nil {
		return result{err: err}
	}
	rmtRel, err := rmtRel(channel)
	if err != nil {
		return result{err: err}
	}
	if release != rmtRel {
		return result{
			val: fmt.Sprintf("Local release %v different from remote %v", release, rmtRel),
			err: fmt.Errorf("Local release %v different from remote %v", release, rmtRel),
		}
	}
	return result{val: fmt.Sprintf("Current release %v is latest on %v", release, channel)}
}

func valFromFile(key, path string) (val string, err error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, key) {
			v := strings.TrimPrefix(line, key)
			return v, nil
		}
	}
	return "", fmt.Errorf("No %s in %s", val, path)
}

func rmtRel(channel string) (release string, err error) {
	uri := fmt.Sprintf(versionUri, channel)
	resp, err := http.Get(uri)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Got %v requesting %v", resp.StatusCode, uri)
	}
	body, err := ioutil.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "COREOS_VERSION=") {
			release = strings.TrimPrefix(line, "COREOS_VERSION=")
			return release, nil
		}
	}
	return "", errors.New("No CoreOS version on the page")
}
