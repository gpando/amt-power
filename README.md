# amt-power

Minimal Go CLI to change the power state of Intel AMT machines out-of-band
(WS-Man `CIM_PowerManagementService.RequestPowerStateChange` over HTTP Digest
auth, port 16992). No AMT credentials are stored; the password is read from
the `AMT_PASSWORD` environment variable.

## Usage

```bash
AMT_PASSWORD="secret" ./bin/amt-power-mac -ip <IP> [-action on|off|off-hard|reboot|reboot-hard] [-user admin] [-port 16992]
```

### Actions (`-action`, default: `on`)

| Action        | CIM PowerState | Description                                      |
|---------------|----------------|--------------------------------------------------|
| `on`          | 2              | Power on                                         |
| `off`         | 12             | Graceful power off (orderly OS shutdown)         |
| `off-hard`    | 8              | Hard power off (like holding the power button)   |
| `reboot`      | 14             | Graceful reboot (orderly OS reset)               |
| `reboot-hard` | 5              | Power cycle (hard off, then on)                  |

> **Note:** the graceful actions (`off`, `reboot`) are only honored when the
> platform advertises PowerState 12/14 in
> `CIM_AssociatedPowerManagementService.AvailableRequestedPowerStates`. If AMT
> rejects them or nothing happens, fall back to `off-hard` / `reboot-hard`.

### Examples

```bash
AMT_PASSWORD="XXXX" ./bin/amt-power-mac -ip 10.0.0.90                # power on (default)
AMT_PASSWORD="XXXX" ./bin/amt-power-mac -ip 10.0.0.90 -action off    # graceful shutdown
AMT_PASSWORD="XXXX" ./bin/amt-power-mac -ip 10.0.0.90 -action reboot # graceful reboot
```

## Build

Run directly from source:

```bash
AMT_PASSWORD="XXXX" go run main.go -ip 10.0.0.90
```

### Cross-compile for all targets

| Binary                       | Target                                     |
|------------------------------|--------------------------------------------|
| `bin/amt-power-mac`         | macOS (Apple Silicon, `darwin/arm64`)      |
| `bin/amt-power-linux-amd64` | Linux x86-64 (`linux/amd64`)               |
| `bin/amt-power-linux-arm64` | Linux ARM64 (`linux/arm64`, e.g. Flint 2)  |

For the Linux targets, CGO is disabled to produce a fully static binary (no
libc/musl dependency) and debug symbols are stripped to minimize size. The
Flint 2 (GL-MT6000) has a MediaTek Filogic 830 (ARM 64-bit) running OpenWrt.

```bash
mkdir -p bin

# macOS (host build)
go build -o bin/amt-power-mac main.go

# Linux x86-64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/amt-power-linux-amd64 main.go

# Linux ARM64 (Flint 2 / OpenWrt)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/amt-power-linux-arm64 main.go
```

## Deploy to the Flint 2 router

```bash
# 1. Copy to the router
cat bin/amt-power-linux-arm64 | ssh root@10.0.0.5 "cat > /usr/bin/amt-power && chmod +x /usr/bin/amt-power"
```

```bash
# 2. Run on the router
AMT_PASSWORD="xxxx" /usr/bin/amt-power -ip 10.0.0.90
```
