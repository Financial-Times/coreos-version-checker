package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	coreosReleaseResponse = `{"securityFixes":[{"id":"CVE-2016-9962","cvss":4.4}],"version":"1284.2.0","releaseNotes":"Security Fixes:\n\n  - Fix RunC privilege escalation ([CVE-2016-9962](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-9962))\n","maxCvss":4.4,"releasedOn":"2017-01-11T01:55:33Z"}`
	releaseConf           = `COREOS_RELEASE_VERSION=1284.2.0
COREOS_RELEASE_BOARD=amd64-usr
COREOS_RELEASE_APPID={e96281a6-d1af-4bde-9a0a-97b76e56dc57}`
	updateConf = `GROUP=stable
REBOOT_STRATEGY=off`
)

type mockClient struct {
	resp       string
	err        error
	statusCode int
}

func (c *mockClient) Do(req *http.Request) (*http.Response, error) {
	cb := ioutil.NopCloser(bytes.NewReader([]byte(c.resp)))
	return &http.Response{Body: cb, StatusCode: c.statusCode}, c.err
}

func TestCoreOS(t *testing.T) {
	repo := newReleaseRepository(&http.Client{}, "/release/conf", "/update/conf")
	coreOS, err := repo.Get("1284.2.0")
	assert.NoError(t, err)

	d, _ := json.Marshal(coreOS)
	assert.Equal(t, coreosReleaseResponse, string(d))
}

func TestCoreOSVersionParsing(t *testing.T) {
	body := `GROUP=stable
COREOS_VERSION=1284.2.0
REBOOT_STRATEGY=off`

	version, err := parseCoreOSVersion(body)

	assert.NoError(t, err)
	assert.Equal(t, "1284.2.0", version)
}

func TestReleaseRepository(t *testing.T) {
	updateFile, _ := ioutil.TempFile("", "update")
	updateFile.Write([]byte(updateConf))
	updateFile.Close()

	releaseFile, _ := ioutil.TempFile("", "release")
	releaseFile.Write([]byte(releaseConf))
	releaseFile.Close()

	defer os.Remove(updateFile.Name())
	repo := newReleaseRepository(&http.Client{}, releaseFile.Name(), updateFile.Name())

	err := repo.GetChannel()
	assert.NoError(t, err)
	assert.Equal(t, "stable", repo.channel)

	err = repo.GetInstalledVersion()
	d, _ := json.Marshal(repo.installedVersion)
	assert.NoError(t, err)
	assert.Equal(t, coreosReleaseResponse, string(d))

	err = repo.GetLatestVersion()
	assert.NoError(t, err)

	assert.NotNil(t, repo.latestVersion)
}

func TestReleaseRepository_UpdateError(t *testing.T) {
	repo := newReleaseRepository(&http.Client{}, "/release/conf", "/update/conf")
	assert.NoError(t, repo.err)

	expErr := errors.New("An expected error")

	repo.UpdateError(expErr)
	assert.Error(t, repo.err)
	assert.Equal(t, expErr, repo.err)

}
