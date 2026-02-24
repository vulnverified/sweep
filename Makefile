VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test clean

build:
	go build -ldflags "$(LDFLAGS)" -o sweep ./cmd/sweep/

test:
	go test -race -count=1 ./...

clean:
	rm -f sweep
