FROM golang:1

ENV PROJECT=coreos-version-checker
ENV ORG_PATH="github.com/Financial-Times"
ENV REPO_PATH="${ORG_PATH}/${PROJECT}"
ENV SRC_FOLDER="${GOPATH}/src/${REPO_PATH}"

COPY . ${SRC_FOLDER}
WORKDIR ${SRC_FOLDER}

RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh \
  && $GOPATH/bin/dep ensure -vendor-only \
  && mkdir -p $GOPATH/src/${ORG_PATH} \
  # Linking the project sources in the GOPATH folder
  && ln -s /${PROJECT}-sources $GOPATH/src/${REPO_PATH} \
  && cd ${SRC_FOLDER} \
  && echo "Fetching dependencies..." \
  && go build  \
  && mv ${PROJECT} /${PROJECT}

# Multi-stage build - copy certs and the binary into the image
FROM scratch

WORKDIR /
COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=0 /${SRC_FOLDER} /

EXPOSE 8080
CMD [ "/coreos-version-checker" ]