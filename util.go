package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type result struct {
	val string
	err error
}

func loop(f func() result, periodS int, resultCh chan<- result) {
	updateCh := make(chan result)
	go func() {
		for {
			updateCh <- f()
			time.Sleep(time.Duration(periodS) * time.Second)
		}
	}()

	result := result{err: errors.New("No value yet")}
	for {
		select {
		case resultCh <- result:
		case result = <-updateCh:
		}
	}
}

// GetJSON performs a GET request using the given client, and parses the response to a map[string]interface{}
func GetJSON(client *http.Client, uri string) (map[string]interface{}, error) {
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
