BINARY=cordclaw-daemon
OUT=bin

.PHONY: build test test-integration tidy release clean

build:
	go build -o $(OUT)/$(BINARY) ./cmd/cordclaw-daemon

test:
	go test ./...

test-integration:
	go test -count=3 -tags=integration ./test/integration/...

tidy:
	go mod tidy

release:
	GOOS=linux GOARCH=amd64 go build -o $(OUT)/$(BINARY)-linux-amd64 ./cmd/cordclaw-daemon
	GOOS=linux GOARCH=arm64 go build -o $(OUT)/$(BINARY)-linux-arm64 ./cmd/cordclaw-daemon
	GOOS=darwin GOARCH=amd64 go build -o $(OUT)/$(BINARY)-darwin-amd64 ./cmd/cordclaw-daemon
	GOOS=darwin GOARCH=arm64 go build -o $(OUT)/$(BINARY)-darwin-arm64 ./cmd/cordclaw-daemon
	GOOS=windows GOARCH=amd64 go build -o $(OUT)/$(BINARY)-windows-amd64.exe ./cmd/cordclaw-daemon

clean:
	rm -rf $(OUT)
