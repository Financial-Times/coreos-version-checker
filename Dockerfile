FROM golang:1

ENV PROJECT=coreos-version-checker
ENV ORG_PATH="github.com/Financial-Times"
ENV REPO_PATH="${ORG_PATH}/${PROJECT}"
ENV SRC_FOLDER="${GOPATH}/src/${REPO_PATH}"

COPY . ${SRC_FOLDER}
WORKDIR ${SRC_FOLDER}

# Fetching dependencies
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh \
  && $GOPATH/bin/dep ensure -vendor-only \
  && CGO_ENABLED=0 go build -a -o /artifacts/${PROJECT}

# Multi-stage build - copy certs and the binary into the image
FROM scratch

WORKDIR /
COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=0 /artifacts/* /

EXPOSE 8080
CMD [ "/coreos-version-checker" ]