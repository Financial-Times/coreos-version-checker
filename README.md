# coreos-version-checker

##Building
```
CGO_ENABLED=0 go build -a -installsuffix cgo -o coreos-version-checker .

docker build -t coco/coreos-version-checker .
```

