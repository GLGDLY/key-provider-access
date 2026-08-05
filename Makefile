PLUGIN_ID := key-model-access
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

ifeq ($(GOOS),darwin)
EXT := dylib
else ifeq ($(GOOS),windows)
EXT := dll
else
EXT := so
endif

ARTIFACT := dist/$(PLUGIN_ID).$(EXT)
CPA_DIR ?=

.PHONY: all build test check install clean

all: check build

build:
	@mkdir -p dist
	CGO_ENABLED=1 go build -buildmode=c-shared -trimpath -o $(ARTIFACT) .
	@rm -f dist/$(PLUGIN_ID).h
	@echo "built $(ARTIFACT)"

test:
	go test ./...

check:
	gofmt -w *.go
	go vet ./...
	go test -race ./...

install: build
	@test -n "$(CPA_DIR)" || (echo "usage: make install CPA_DIR=/path/to/CLIProxyAPI"; exit 1)
	@mkdir -p "$(CPA_DIR)/plugins/$(GOOS)/$(GOARCH)"
	cp $(ARTIFACT) "$(CPA_DIR)/plugins/$(GOOS)/$(GOARCH)/$(PLUGIN_ID).$(EXT)"
	@echo "installed to $(CPA_DIR)/plugins/$(GOOS)/$(GOARCH)/$(PLUGIN_ID).$(EXT)"

clean:
	rm -rf dist
