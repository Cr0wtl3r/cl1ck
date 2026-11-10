build:
	go build -o cl1ck ./cmd/cl1ck

test:
	go test ./...

test-browser:
	go test -tags browser ./internal/browser/

vet:
	go vet ./...

check: vet test

clean:
	rm -f cl1ck
	rm -rf evidencias

.PHONY: build test test-browser vet check clean
