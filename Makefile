.PHONY: build run docker test clean

BINARY=appoller
VERSION=1.0.0

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY) ./cmd/main.go

run:
	go run ./cmd/main.go

docker:
	docker build -t alertpriority/appoller:$(VERSION) .

test:
	go test ./...

clean:
	rm -f $(BINARY)
