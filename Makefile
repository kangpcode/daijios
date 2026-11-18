# DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)
# Build, Cross-Compile, Test & Audit Makefile

APP := daiji-ctl
NETD := daiji-netd
FWQOSD := daiji-fw-qosd
ISPD := daiji-ispd
AC := daiji-ac
SH := daiji-sh
WEBD := daiji-webd
PKG := ./cmd/daiji-ctl
NETD_PKG := ./services/daiji-netd
FWQOSD_PKG := ./services/daiji-fw-qosd
ISPD_PKG := ./services/daiji-ispd
AC_PKG := ./services/daiji-ac
SH_PKG := ./services/daiji-sh
WEBD_PKG := ./services/daiji-webd
VERSION ?= 0.7.0-phase6
LDFLAGS := -s -w -X github.com/kangpcode/daijios/pkg/sysinfo.Version=$(VERSION)

.PHONY: all build test test-race bench vet check cross-build clean

all: vet test-race build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP) $(PKG)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(NETD) $(NETD_PKG)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(FWQOSD) $(FWQOSD_PKG)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(ISPD) $(ISPD_PKG)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(AC) $(AC_PKG)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(SH) $(SH_PKG)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(WEBD) $(WEBD_PKG)

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
		env CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $$env_var go build -trimpath -ldflags "$(LDFLAGS)" -o bin/dist/$(ISPD)-linux-$$suffix $(ISPD_PKG) || exit 1; \
		env CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $$env_var go build -trimpath -ldflags "$(LDFLAGS)" -o bin/dist/$(AC)-linux-$$suffix $(AC_PKG) || exit 1; \
		env CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $$env_var go build -trimpath -ldflags "$(LDFLAGS)" -o bin/dist/$(SH)-linux-$$suffix $(SH_PKG) || exit 1; \
		env CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $$env_var go build -trimpath -ldflags "$(LDFLAGS)" -o bin/dist/$(WEBD)-linux-$$suffix $(WEBD_PKG) || exit 1; \
	done
	@ls -lh bin/dist/

clean:
	rm -rf bin coverage.out
