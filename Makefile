PLUGIN_NAME := solace-vault-plugin
PLUGIN_DIR := bin

.PHONY: build clean test fmt

build:
	go build -o $(PLUGIN_DIR)/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)

clean:
	rm -rf $(PLUGIN_DIR)

test:
	go test -v -race ./...

fmt:
	go fmt ./...
