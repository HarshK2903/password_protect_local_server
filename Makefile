.PHONY: build test race fuzz vet check clean

build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/fileshare ./cmd/fileshare

test:
	go test ./...

race:
	go test -race ./...

fuzz:
	go test ./internal/files -run='^$$' -fuzz=FuzzConfinedPaths -fuzztime=15s -parallel=2

vet:
	go vet ./...

check: vet test race

clean:
	rm -rf bin
