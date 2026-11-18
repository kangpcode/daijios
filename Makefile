# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)
# Build, Cross-Compile, Test & Audit Makefile

APP := daiji-ctl
NETD := daiji-netd
FWQOSD := daiji-fw-qosd
PKG := ./cmd/daiji-ctl
NETD_PKG := ./services/daiji-netd
FWQOSD_PKG := ./services/daiji-fw-qosd
VERSION ?= 0.3.0-phase2
LDFLAGS := -s -w -X github.com/kangpcode/daijios/pkg/sysinfo.Version=$(VERSION)

.PHONY: all build test test-race bench vet check cross-build clean

all: vet test-race build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP) $(PKG)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(NETD) $(NETD_PKG)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(FWQOSD) $(FWQOSD_PKG)

test:
	go test -v ./...

test-race:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

bench:
	go test -bench=. -benchmem ./pkg/...

vet:
	go vet ./...

check: vet test-race bench

# Cross-compile static binaries for all supported hardware targets
cross-build:
	@mkdir -p bin/dist
	for arch_spec in "amd64:" "arm64:" "arm:GOARM=7" "mipsle:GOMIPS=softfloat" "mips64le:GOMIPS64=softfloat"; do \
		arch=$${arch_spec%%:*}; env_var=$${arch_spec#*:}; \
		suffix=$$arch; [ "$$arch" = "arm" ] && suffix="armv7"; [ "$$arch" = "mipsle" ] && suffix="mipsel"; \
		env CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $$env_var go build -trimpath -ldflags "$(LDFLAGS)" -o bin/dist/$(APP)-linux-$$suffix $(PKG) || exit 1; \
		env CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $$env_var go build -trimpath -ldflags "$(LDFLAGS)" -o bin/dist/$(NETD)-linux-$$suffix $(NETD_PKG) || exit 1; \
		env CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $$env_var go build -trimpath -ldflags "$(LDFLAGS)" -o bin/dist/$(FWQOSD)-linux-$$suffix $(FWQOSD_PKG) || exit 1; \
	done
	@ls -lh bin/dist/

clean:
	rm -rf bin coverage.out
