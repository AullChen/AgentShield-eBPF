BINARY := bin/agentshield

ifeq ($(OS),Windows_NT)
BINARY := bin/agentshield.exe
endif

.PHONY: generate check-bpf-syntax test build clean

generate:
	go generate ./internal/bpfmgr

check-bpf-syntax:
	clang -DAGENTSHIELD_BPF_SYNTAX_CHECK -fsyntax-only bpf/agentshield.bpf.c

test:
	go test ./...

build: bin
	go build -o $(BINARY) ./cmd/agentshield

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
