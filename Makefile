.PHONY: test lint fmt

test:
	go test ./...

lint:
	golangci-lint run ./...

fmt:
	nix fmt
