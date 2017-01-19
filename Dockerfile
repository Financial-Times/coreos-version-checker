FROM alpine:3.5
ADD . /
RUN apk --update add go git libc-dev \
  && ORG_PATH="github.com/Financial-Times" \
  && REPO_PATH="${ORG_PATH}/coreos-version-checker" \
  && export GOPATH=/gopath \
  && mkdir -p $GOPATH/src/${ORG_PATH} \
  && ln -s ${PWD} $GOPATH/src/${REPO_PATH} \
  && cd $GOPATH/src/${REPO_PATH} \
  && go get \
  && go build -a -ldflags "-s" -o /coreos-version-checker ${REPO_PATH} \
  && apk del go git \
  && rm -rf $GOPATH /var/cache/apk/*

EXPOSE 8080
CMD ["/coreos-version-checker"]
