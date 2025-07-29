# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v 
LDFLAGS := -s -w

ifneq ($(shell go env GOOS),darwin)
LDFLAGS := -extldflags "-static"
endif
    
all: build
build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "httpx" cmd/httpx/httpx.go
test: 
	$(GOTEST) $(GOFLAGS) ./...
tidy:
	$(GOMOD) tidy
release:
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -trimpath -o "dist/httpx-linux-amd64" cmd/httpx/httpx.go
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -trimpath -o "dist/httpx-linux-arm64" cmd/httpx/httpx.go
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -trimpath -o "dist/httpx-darwin-amd64" cmd/httpx/httpx.go
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -trimpath -o "dist/httpx-darwin-arm64" cmd/httpx/httpx.go
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -trimpath -o "dist/httpx-windows-amd64.exe" cmd/httpx/httpx.go
	GOOS=windows GOARCH=arm64 $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -trimpath -o "dist/httpx-windows-arm64.exe" cmd/httpx/httpx.go
	@echo "Release build completed. Binaries are located in the dist/ directory."
