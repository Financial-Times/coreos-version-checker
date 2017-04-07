package main

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
)

var cveRegex = regexp.MustCompile(`CVE\-[0-9]{4}\-[0-9]{4,}`)

const (
	cveUri      string = "http://cve.circl.lu/api/cve/%s"
	releasesUri string = "https://coreos.com/releases/releases.json"
)

type cve struct {
	ID   string  `json:"id"`
	CVSS float64 `json:"cvss"`
	err  error
}

type coreOSRelease struct {
	SecurityFixes []cve    `json:"securityFixes,omitempty"`
	Version       string   `json:"version"`
	MaxCVSS       *float64 `json:"maxCvss,omitempty"`
	ReleaseNotes  string   `json:"releaseNotes"`
}

type releaseRepository struct {
	client *http.Client
}

func newReleaseRepository(client *http.Client) *releaseRepository {
	return &releaseRepository{client}
}

func (r *releaseRepository) Get(release string) (*coreOSRelease, error) {
	releases, err := GetJSON(r.client, releasesUri)
	if err != nil {
		return nil, err
	}

	releaseData := releases[release].(map[string]interface{})
	releaseNotes := releaseData["release_notes"].(string)

	cveIDs := parseReleaseNotes(releaseNotes)
	var securityFixes []cve
	var maxCVSS float64 = -1

	for _, cveID := range cveIDs {
		fix := r.retrieveCVE(cveID)
		securityFixes = append(securityFixes, fix)
		maxCVSS = math.Max(maxCVSS, fix.CVSS)
	}

	if maxCVSS == -1 {
		return &coreOSRelease{ReleaseNotes: releaseNotes, SecurityFixes: securityFixes, Version: release}, nil
	}

	return &coreOSRelease{ReleaseNotes: releaseNotes, SecurityFixes: securityFixes, MaxCVSS: &maxCVSS, Version: release}, nil
}

func parseReleaseNotes(notes string) []string {
	cveIDs := cveRegex.FindAllString(notes, -1)
	if len(cveIDs) == 0 {
		return cveIDs
	}

	uniqueCVEs := make(map[string]struct{})
	for _, cveID := range cveIDs {
		uniqueCVEs[cveID] = struct{}{}
	}

	result := make([]string, 0)
	for cveID := range uniqueCVEs {
		result = append(result, cveID)
	}
	return result
}

func (r *releaseRepository) retrieveCVE(id string) cve {
	cveResult, err := GetJSON(r.client, fmt.Sprintf(cveUri, id))
	if err != nil {
		return cve{err: err, ID: id}
	}

	cvssRaw, ok := cveResult["cvss"]
	if !ok {
		return cve{err: errors.New("No CVSS found!"), ID: id}
	}

	score, err := strconv.ParseFloat(cvssRaw.(string), 64)
	if err != nil {
		return cve{err: err, ID: id}
	}

	return cve{CVSS: score, ID: id, err: nil}
}
