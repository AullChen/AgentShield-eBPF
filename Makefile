BINARY := bin/agentshield
BPF_OBJECT := bpf/agentshield.bpf.o
BPF_MANIFEST := bpf/agentshield.bpf.manifest.json

ifeq ($(OS),Windows_NT)
BINARY := bin/agentshield.exe
endif

.PHONY: generate verify-generated bpf-object verify-bpf-object accept-p1 accept-p2 accept-network-block accept-sandbox test-p2 test-p3 test-checkpoint check-bpf-syntax check-linux-bpfmgr check-linux-killer check-linux-api test build check clean

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

test-p2:
	go test ./internal/api -run '^TestP2LifecycleAcceptance$$' -count=1

test-p3:
	go test ./internal/api -run '^Test(P3Acceptance|PolicyCoordinator.*)$$' -count=1
	go test ./internal/policy -count=1

test-checkpoint:
	go test ./internal/api -run '^TestCheckpoint' -count=1

accept-p2: bpf-object build
	sudo ./scripts/accept-p2.sh $(BPF_OBJECT) $(BPF_MANIFEST)

accept-network-block: bpf-object build
	sudo ./scripts/accept-network-block.sh $(BPF_OBJECT)

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

check-linux-killer: bin
ifeq ($(OS),Windows_NT)
	set GOOS=linux&& set GOARCH=amd64&& go test -c -o bin/killer_linux.test ./internal/killer
	set GOOS=linux&& set GOARCH=amd64&& go test -c -o bin/scope_linux.test ./internal/scope
else
	GOOS=linux GOARCH=amd64 go test -c -o bin/killer_linux.test ./internal/killer
	GOOS=linux GOARCH=amd64 go test -c -o bin/scope_linux.test ./internal/scope
endif

check-linux-api: bin
ifeq ($(OS),Windows_NT)
	set GOOS=linux&& set GOARCH=amd64&& go test -c -o bin/api_linux.test ./internal/api
else
	GOOS=linux GOARCH=amd64 go test -c -o bin/api_linux.test ./internal/api
endif

test:
	go test ./...

build: bin
	go build -o $(BINARY) ./cmd/agentshield

check: verify-generated check-bpf-syntax check-linux-bpfmgr check-linux-killer check-linux-api test build

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
