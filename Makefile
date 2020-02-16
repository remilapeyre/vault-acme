GOX_OS := linux darwin windows freebsd openbsd solaris
TEST_ARGS :=

.PHONY: build
build:
	@mkdir -p build
	go build -o build ./...

.PHONY: fmt
fmt:
	gofmt -w acme

.PHONY: clean
clean:
	rm -rf build/*

.PHONY: test
test:
	@./test/run_tests.sh $(TEST_ARGS)

.PHONY: testacc
testacc: build
	@./test/run_acceptance_tests.sh $(TEST_ARGS)

.PHONY: website
website:
	$(MAKE) -C website build

.PHONY: preview
preview:
	$(MAKE) -C website website

.PHONY: all
all:
	gox -os='$(GOX_OS)' -arch='386 amd64 arm' -osarch='!darwin/arm !darwin/386' -output 'build/{{.OS}}_{{.Arch}}/acme-plugin' ./cmd/acme
	gox -os='$(GOX_OS)' -arch='386 amd64 arm' -osarch='!darwin/arm !darwin/386' -output 'build/{{.OS}}_{{.Arch}}/sidecar' ./cmd/sidecar
