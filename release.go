package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

var cveRegex = regexp.MustCompile(`CVE\-[0-9]{4}\-[0-9]{4,}`)

const (
	cveURI            string = "http://cve.circl.lu/api/cve/%s"
	betaReleasesURI   string = "https://coreos.com/releases/releases.json"
	stableReleasesURI string = "https://coreos.com/releases/releases-stable.json"
)

type cve struct {
	ID   string  `json:"id"`
	CVSS float64 `json:"cvss"`
	err  error
}

type coreOSRelease struct {
	SecurityFixes []cve      `json:"securityFixes,omitempty"`
	Version       string     `json:"version"`
	ReleaseNotes  string     `json:"releaseNotes"`
	MaxCVSS       *float64   `json:"maxCvss,omitempty"`
	ReleaseDate   *time.Time `json:"releaseDate,omitempty"`
}

type releaseRepository struct {
	sync.RWMutex
	client           *retryablehttp.Client
	channel          string
	installedVersion coreOSRelease
	latestVersion    coreOSRelease
	err              error
	releaseConfPath  string
	updateConfPath   string
}

func newReleaseRepository(client *http.Client, releaseConfPath string, updateConfPath string) *releaseRepository {
	retryableClient := &retryablehttp.Client{
		HTTPClient:   client,
		Logger:       log.New(ioutil.Discard, "", log.LstdFlags),
		RetryWaitMin: 100 * time.Millisecond,
		RetryWaitMax: 2 * time.Second,
		RetryMax:     5,
		CheckRetry:   retryablehttp.DefaultRetryPolicy,
		Backoff:      retryablehttp.DefaultBackoff,
	}
	return &releaseRepository{
		client:          retryableClient,
		releaseConfPath: releaseConfPath,
		updateConfPath:  updateConfPath,
	}
}

func (r *releaseRepository) UpdateError(err error) {
	r.Lock()
	defer r.Unlock()
	r.err = err
}

func (r *releaseRepository) GetChannel() error {
	channel, err := getValueFromFile("GROUP=", r.updateConfPath)
	if err != nil {
		return err
	}

	r.Lock()
	defer r.Unlock()
	// in K8S we use CoreUpdate, which uses a non-standard channel, like "coreUpdateChan1"
	// if we encounter a non-standard channel, we default the channel to "stable"
	if channel == "beta" || channel == "alpha" {
		r.channel = channel
	} else {
		r.channel = "stable"
	}
	return nil
}

func (r *releaseRepository) GetInstalledVersion() error {
	release, err := getValueFromFile("COREOS_RELEASE_VERSION=", r.releaseConfPath)
	if err != nil {
		return err
	}
	log.Printf("GetInstalledVersion(): currently installed version is %v", release)

	releases, err := GetJSON(r.client, betaReleasesURI)
	if err != nil {
		return err
	}

	enrichedRelease, err := r.GetReleaseData(release, releases)
	if err != nil {
		return err
	}

	r.Lock()
	defer r.Unlock()

	r.installedVersion = *enrichedRelease
	return nil
}

func (r *releaseRepository) GetLatestVersion() error {
	releases, err := GetJSON(r.client, stableReleasesURI)
	if err != nil {
		return err
	}

	release, err := getLatestReleaseFromJSON(releases)
	if err != nil {
		return err
	}

	coreOS, err := r.GetReleaseData(release, releases)
	if err != nil {
		return err
	}

	r.Lock()
	defer r.Unlock()

	r.latestVersion = *coreOS
	return nil
}

func (r *releaseRepository) GetReleaseData(release string, releases map[string]interface{}) (*coreOSRelease, error) {

	releaseData, ok := releases[release].(map[string]interface{})
	if !ok {
		return nil, errors.New("Release not found")
	}

	releaseNotes := releaseData["release_notes"].(string)
	releasedOnText, ok := releaseData["release_date"]

	var releaseDate *time.Time
	if ok {
		parsed, err := time.Parse("2006-01-02 15:04:05 -0700", releasedOnText.(string))
		if err == nil {
			releaseDate = &parsed
		}
	}

	cveIDs := parseReleaseNotes(releaseNotes)
	var securityFixes []cve
	var maxCVSS float64 = -1

	for _, cveID := range cveIDs {
		fix := r.retrieveCVE(cveID)
		securityFixes = append(securityFixes, fix)
		maxCVSS = math.Max(maxCVSS, fix.CVSS)
	}
	return &coreOSRelease{ReleaseDate: releaseDate, ReleaseNotes: releaseNotes, SecurityFixes: securityFixes, MaxCVSS: &maxCVSS, Version: release}, nil
}

func getLatestReleaseFromJSON(m map[string]interface{}) (string, error) {
	versions := make([]string, 0, len(m))
	for key := range m {
		versions = append(versions, key)
	}
	padded := padReleases(versions)
	sort.Strings(padded)

	if len(padded) > 0 {
		p := padded[len(padded)-1]
		version := cutPaddedRelease(p)
		return version, nil
	}
	return "", errors.New("Version is empty")
}

func padReleases(releases []string) []string {
	paddedStrings := make([]string, 0, len(releases))
	for k := range releases {
		var builder strings.Builder
		splitVersions := strings.Split(releases[k], ".")
		for s := range splitVersions {
			padded := leftPad(splitVersions[s], "*", 5)
			if splitVersions[s] != splitVersions[len(splitVersions)-1] {
				builder.WriteString(padded + ".")
			} else {
				builder.WriteString(padded)
			}
		}
		paddedStrings = append(paddedStrings, builder.String())
	}
	return paddedStrings
}

func leftPad(s string, padStr string, totalLen int) string {
	padCount := 1 + ((totalLen - len(padStr)) / len(padStr))
	res := strings.Repeat(padStr, padCount) + s
	return res[(len(res) - totalLen):]
}

func cutPaddedRelease(padded string) string {
	var builder strings.Builder
	paddedStrings := strings.Split(padded, ".")
	for k := range paddedStrings {
		temp := paddedStrings[k]
		in := strings.LastIndex(temp, "*")
		temp = temp[(in + 1):] //cut special symbols
		if paddedStrings[k] != paddedStrings[len(paddedStrings)-1] {
			builder.WriteString(temp + ".")
		} else {
			builder.WriteString(temp)
		}
	}
	return builder.String()
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
	cveResult, err := GetJSON(r.client, fmt.Sprintf(cveURI, id))
	if err != nil {
		return cve{err: err, ID: id}
	}

	cvssString, ok := cveResult["cvss"].(string)
	if !ok {
		return cve{err: errors.New("No CVSS found!"), ID: id}
	}
	cvss, err := strconv.ParseFloat(cvssString, 64)
	if err != nil {
		return cve{
			err: errors.New(fmt.Sprintf("Cannot parse CVSS %s because %v", cvssString, err.Error())),
			ID:  id,
		}
	}
	return cve{CVSS: cvss, ID: id, err: nil}
}
