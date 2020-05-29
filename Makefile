BINARY := trapdoor

GO_ASSETS := assets_vfsdata.go
GO_SOURCES := $(shell find . -type f -name '*.go' -not -name '*_test.go' -not -name $(GO_ASSETS))
ifneq ($(filter embed,$(GO_TAGS)),)
  GO_SOURCES += $(GO_ASSETS)
endif

GIT_COMMIT := $(shell git rev-parse HEAD)
VERSION := $(patsubst v%,%,$(shell git describe --always --match 'v*'))
GO_LDFLAGS := -X main.GitCommit=$(GIT_COMMIT) -X main.Version=$(VERSION)

JS_SOURCES := index.js terminal.js

$(BINARY): $(GO_SOURCES) go.sum
	go build -o $@ -ldflags '$(GO_LDFLAGS)' -tags '$(GO_TAGS)'

$(GO_ASSETS): assets.go assets_generate.go js/index.js
	go generate

js/index.js: $(JS_SOURCES) package.json webpack.config.js yarn.lock
	yarn build

.PHONY: clean
clean:
	rm -rf $(BINARY) $(GO_ASSETS) js
