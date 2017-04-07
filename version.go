package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

var versionCh chan result

type versionChecker struct{}

func (v versionChecker) Check() (string, error) {
	result := <-versionCh
	return result.val, result.err
}

func latest() result {
	channel, err := valueFromFile("GROUP=", *hostPath+"/etc/coreos/update.conf")
	if err != nil {
		return result{err: err}
	}

	release, err := valueFromFile("COREOS_RELEASE_VERSION=", *hostPath+"/usr/share/coreos/release")
	if err != nil {
		return result{err: err}
	}

	rmtRel, err := remoteRelease(channel)
	if err != nil {
		return result{err: err}
	}

	if release != rmtRel {

	}

	return result{val: fmt.Sprintf("Current release %v is latest on %v", release, channel)}
}

func valueFromFile(key, path string) (val string, err error) {
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

func remoteRelease(channel string) (release string, err error) {
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
