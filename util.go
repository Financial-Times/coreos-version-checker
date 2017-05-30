package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

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

// GetJSON performs a GET request using the given client, and parses the response to a map[string]interface{}
func GetJSON(client httpClient, uri string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(resp.Body)
	data := make(map[string]interface{})

	err = dec.Decode(&data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
