package main

import (
	"net/http"
	"os"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/jawher/mow.cli"
)

var (
	coreOSUpdateConfPath  *string
	coreOSReleaseConfPath *string
)

const (
	versionUri string = "http://%s.release.core-os.net/amd64-usr/current/version.txt"
)

func main() {
	app := cli.App("coreos-version-checker", "Checks for new CoreOS upgrades, and reports on the CVE severity score.")

	coreOSUpdateConfPath = app.String(cli.StringOpt{
		Name:   "update-conf",
		Value:  "/etc/coreos/update.conf",
		Desc:   "The location of the CoreOS update.conf file.",
		EnvVar: "UPDATE_CONF",
	})

	coreOSReleaseConfPath = app.String(cli.StringOpt{
		Name:   "release-conf",
		Value:  "/usr/share/coreos/release",
		Desc:   "The location of the CoreOS release file.",
		EnvVar: "RELEASE_CONF",
	})

	app.Action = func() {
		log.WithField("update-conf", *coreOSUpdateConfPath).WithField("release-conf", *coreOSReleaseConfPath).Info("Started with provided config.")

		client := &http.Client{Timeout: 1500 * time.Millisecond}
		repo := newReleaseRepository(client)

		go startPoll(time.Minute*5, repo)

		mux := mux.NewRouter()
		mux.HandleFunc("/__health", Health(repo)).Methods("GET")

		log.Printf("Starting http server on 8080\n")
		err := http.ListenAndServe(":8080", mux)
		if err != nil {
			panic(err)
		}
	}

	app.Run(os.Args)
}

func startPoll(interval time.Duration, repo *releaseRepository) {
	err := pollCoreOSReleases(repo)
	repo.UpdateError(err)

	poll := time.NewTicker(interval)
	for {
		<-poll.C
		err := pollCoreOSReleases(repo)
		repo.UpdateError(err)
	}
}

func pollCoreOSReleases(repo *releaseRepository) error {
	err := repo.GetChannel()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve the channel from CoreOS update.conf!")
		return err
	}

	err = repo.GetInstalledVersion()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve the currently installed version!")
		return err
	}

	err = repo.GetLatestVersion()
	if err != nil {
		log.WithError(err).Error("Failed to retrieve the latest remote coreOS Release!")
		return err
	}

	return nil
}
