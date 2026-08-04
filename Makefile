.PHONY: test vet build check

test:
	go test ./...

vet:
	go vet ./...

build:
	go build -o beforerun ./cmd/beforerun

check: vet test build
