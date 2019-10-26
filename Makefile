vault := VAULT_ADDR=http://localhost:8200 vault
server_url := https://acme-staging-v02.api.letsencrypt.org/directory
GOX_OS := linux darwin windows freebsd openbsd solaris
TEST_ARGS :=

.PHONY: build
build:
	go build -o acme-plugin

.PHONY: install
install: build
	@$(vault) secrets disable acme/ >/dev/null || true
	@$(vault) write sys/plugins/catalog/secret/acme sha_256=$$(shasum -a 256 acme-plugin | cut -d ' ' -f1) command=acme-plugin >/dev/null
	$(vault) secrets enable -path=acme -plugin-name=acme plugin >/dev/null

.PHONY: clean
clean:
	rm -f acme-plugin

.PHONY: test
test:
	go test $(TEST_ARGS) ./acme

.PHONY: website
website:
	$(MAKE) -C website build

.PHONY: preview
preview:
	$(MAKE) -C website website

.PHONY: all
all:
	gox -os='$(GOX_OS)' -arch='386 amd64 arm' -osarch='!darwin/arm !darwin/386' -output 'build/{{.OS}}_{{.Arch}}/acme-plugin' .
