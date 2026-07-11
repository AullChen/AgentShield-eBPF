BINARY := bin/agentshield

ifeq ($(OS),Windows_NT)
BINARY := bin/agentshield.exe
endif

.PHONY: generate verify-generated check-bpf-syntax check-linux-bpfmgr test build check clean

generate:
	go generate ./internal/bpfmgr

verify-generated:
	go test ./internal/bpfmgr -run TestEmbeddedSourcesMatchWorkingTree -count=1

check-bpf-syntax:
	clang -DAGENTSHIELD_BPF_SYNTAX_CHECK -fsyntax-only bpf/agentshield.bpf.c

check-linux-bpfmgr: bin
ifeq ($(OS),Windows_NT)
	set GOOS=linux&& set GOARCH=amd64&& go test -c -o bin/bpfmgr_linux.test ./internal/bpfmgr
else
	GOOS=linux GOARCH=amd64 go test -c -o bin/bpfmgr_linux.test ./internal/bpfmgr
endif

test:
	go test ./...

build: bin
	go build -o $(BINARY) ./cmd/agentshield

check: verify-generated check-bpf-syntax check-linux-bpfmgr test build

bin:
ifeq ($(OS),Windows_NT)
	@if not exist bin mkdir bin
else
	@mkdir -p bin
endif

clean:
ifeq ($(OS),Windows_NT)
	@if exist bin rmdir /s /q bin
else
	@rm -rf bin
endif
