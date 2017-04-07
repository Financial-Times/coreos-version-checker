package main

import (
	"log"
	"net/http"
	"time"

	fthealth "github.com/Financial-Times/go-fthealth/v1a"
	"github.com/gorilla/mux"
	"github.com/jawher/mow.cli"
)

var (
	checks   []fthealth.Check
	hostPath *string
)

const (
	versionUri string = "http://%s.release.core-os.net/amd64-usr/current/version.txt"
)

func main() {
	app := cli.App("CoreOS-version-checker", "A service that report on current VM status at __health")

	hostPath = app.String(cli.StringOpt{
		Name:   "hostPath",
		Value:  "",
		Desc:   "The dir path of the mounted host fs (in the container)",
		EnvVar: "SYS_HC_HOST_PATH",
	})

	client := &http.Client{Timeout: 1500 * time.Millisecond}
	newReleaseRepository(client)

	checks = append(checks, versionChecker{}.Checks()...)

	mux := mux.NewRouter()
	mux.HandleFunc("/__health", fthealth.Handler("myserver", "a server", checks...))

	log.Printf("Starting http server on 8080\n")
	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		panic(err)
	}
}
