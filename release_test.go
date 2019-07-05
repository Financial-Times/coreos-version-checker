package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/jarcoal/httpmock.v1"
)

var (
	coreosReleaseHTTPResponse = `
	{"2135.5.0": {
		"version": "2135.5.0",
		"release_notes": "Bug fixes:\n\n * Fix Ignition panic when no guestinfo.(coreos|ignition).config parameters are specified on VMware (coreos/ignition#821)\n\nUpdates:\n\n * Ignition [0.33.0](https://github.com/coreos/ignition/releases/tag/v0.33.0)\n",
		"max_cvss":-1,
		"released_on": "2019-07-02T20:52:42Z"
	}}`
	coreosReleaseResponse = `{"version":"2135.5.0","release_notes": "Bug fixes:\n\n * Fix Ignition panic when no guestinfo.(coreos|ignition).config parameters are specified on VMware (coreos/ignition#821)\n\nUpdates:\n\n * Ignition [0.33.0](https://github.com/coreos/ignition/releases/tag/v0.33.0)\n","max_cvss": -1,"released_on": "2019-07-02T20:52:42Z"}`
	releaseConf           = `COREOS_RELEASE_VERSION=2135.5.0
COREOS_RELEASE_BOARD=amd64-usr
COREOS_RELEASE_APPID={e96281a6-d1af-4bde-9a0a-97b76e56dc57}`
)

func TestCoreOS(t *testing.T) {
	repo := newReleaseRepository(&http.Client{}, "/release/conf", "/update/conf")
	releases, err := GetJSON(repo.client, releasesUri)
	assert.NoError(t, err)

	coreOS, err := repo.GetReleaseData("2135.5.0", releases)
	assert.NoError(t, err)

	d, _ := json.Marshal(coreOS)
	assert.Equal(t, coreosReleaseResponse, string(d))
}

func TestReleaseRepository(t *testing.T) {
	var testCases = []struct {
		updateConf      string
		expectedChannel string
	}{
		{
			updateConf:      "GROUP=stable\nREBOOT_STRATEGY=off",
			expectedChannel: "stable",
		},
		{
			updateConf:      "GROUP=beta\nREBOOT_STRATEGY=off",
			expectedChannel: "beta",
		},
		{
			updateConf:      "GROUP=alpha\nREBOOT_STRATEGY=off",
			expectedChannel: "alpha",
		},
		{
			updateConf:      "GROUP=coreUpdateNonStandard1\nREBOOT_STRATEGY=off",
			expectedChannel: "stable",
		},
	}

	releaseFile, _ := ioutil.TempFile("", "release")
	releaseFile.Write([]byte(releaseConf))
	releaseFile.Close()
	defer os.Remove(releaseFile.Name())
	for _, tc := range testCases {
		updateFile, _ := ioutil.TempFile("", "update")
		updateFile.Write([]byte(tc.updateConf))
		updateFile.Close()

		repo := newReleaseRepository(&http.Client{}, releaseFile.Name(), updateFile.Name())

		err := repo.GetChannel()
		assert.NoError(t, err)
		assert.Equal(t, tc.expectedChannel, repo.channel)

		err = repo.GetInstalledVersion()
		d, _ := json.Marshal(repo.installedVersion)
		assert.NoError(t, err)
		assert.Equal(t, coreosReleaseResponse, string(d))

		err = repo.GetLatestVersion()
		assert.NoError(t, err)

		assert.NotNil(t, repo.latestVersion)
		os.Remove(updateFile.Name())
	}
}

func TestReleaseRepositoryRetries(t *testing.T) {
	updateConf := "GROUP=coreUpdateNonStandard1\nREBOOT_STRATEGY=off"
	expectedChannel := "stable"

	releaseFile, _ := ioutil.TempFile("", "release")
	releaseFile.Write([]byte(releaseConf))
	releaseFile.Close()
	defer os.Remove(releaseFile.Name())

	updateFile, _ := ioutil.TempFile("", "update")
	updateFile.Write([]byte(updateConf))
	updateFile.Close()
	defer os.Remove(updateFile.Name())

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", releasesUri,
		func(req *http.Request) (*http.Response, error) {
			resp := httpmock.NewStringResponse(200, coreosReleaseHTTPResponse)
			return resp, nil
		},
	)

	httpmock.RegisterResponder("GET", "http://cve.circl.lu/api/cve/CVE-2016-9962",
		func(req *http.Request) (*http.Response, error) {
			resp := httpmock.NewStringResponse(200, "{}")
			return resp, nil
		},
	)

	//failForAttempts := 10
	//attempt := 0

	// httpmock.RegisterResponder("GET", "http://stable.release.core-os.net/amd64-usr/current/version.txt",
	// 	func(req *http.Request) (*http.Response, error) {
	// 		attempt++
	// 		if attempt <= failForAttempts {
	// 			return nil, errors.New("random error")
	// 		}
	// 		body := "COREOS_VERSION=1284.2.0"
	// 		resp := httpmock.NewStringResponse(200, body)
	// 		return resp, nil
	// 	},
	//)

	repo := newReleaseRepository(
		&http.Client{},
		releaseFile.Name(),
		updateFile.Name(),
	)

	err := repo.GetChannel()
	assert.NoError(t, err)
	assert.Equal(t, expectedChannel, repo.channel)

	err = repo.GetInstalledVersion()
	assert.NoError(t, err)

	err = repo.GetLatestVersion()
	assert.Contains(t, err.Error(), "giving up")

	failForAttempts := 3
	attempt := 0

	err = repo.GetLatestVersion()
	assert.NoError(t, err)

	assert.NotNil(t, repo.latestVersion)
}

func TestNoReleaseForVersion(t *testing.T) {
	repo := newReleaseRepository(&http.Client{}, "/release/conf", "/update/conf")
	assert.NoError(t, repo.err)
	releases, err := GetJSON(repo.client, releasesUri)
	assert.NoError(t, repo.err)

	os, err := repo.GetReleaseData("1.1.1", releases)
	assert.EqualError(t, err, "Release not found")
	assert.Nil(t, os)
}

func TestReleaseRepository_UpdateError(t *testing.T) {
	repo := newReleaseRepository(&http.Client{}, "/release/conf", "/update/conf")
	assert.NoError(t, repo.err)

	expErr := errors.New("An expected error")

	repo.UpdateError(expErr)
	assert.Error(t, repo.err)
	assert.Equal(t, expErr, repo.err)
}
