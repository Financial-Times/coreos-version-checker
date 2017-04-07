package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCoreOS(t *testing.T) {
	repo := newReleaseRepository(&http.Client{})
	coreOS, err := repo.Get("1284.2.0")
	assert.NoError(t, err)

	d, _ := json.Marshal(coreOS)
	t.Log(string(d))
}
