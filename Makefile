BINARY := bin/agentshield
BPF_OBJECT := bpf/agentshield.bpf.o
BPF_MANIFEST := bpf/agentshield.bpf.manifest.json

ifeq ($(OS),Windows_NT)
BINARY := bin/agentshield.exe
endif

.PHONY: generate verify-generated bpf-object verify-bpf-object accept-p1 accept-sandbox check-bpf-syntax check-linux-bpfmgr test build check clean

generate:
	go generate ./internal/bpfmgr

verify-generated:
	go test ./internal/bpfmgr -run TestEmbeddedSourcesMatchWorkingTree -count=1

bpf-object:
	./scripts/build-bpf.sh $(BPF_OBJECT) $(BPF_MANIFEST)

verify-bpf-object:
	go run ./cmd/bpfcheck --object $(BPF_OBJECT) --verify-manifest $(BPF_MANIFEST)

accept-p1: bpf-object build
	sudo ./scripts/accept-p1.sh $(BPF_OBJECT) $(BPF_MANIFEST)

accept-sandbox:
	./scripts/accept-sandbox.sh

check-bpf-syntax:
	clang -DAGENTSHIELD_BPF_SYNTAX_CHECK -Wall -Wextra -Werror -Wno-unused-parameter -fsyntax-only bpf/agentshield.bpf.c

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
