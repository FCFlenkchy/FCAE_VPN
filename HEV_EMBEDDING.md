# Embedding hev-socks5-tunnel

## Overview

The hev-socks5-tunnel is used as an embedded resource for TUN support on Linux and Windows. Instead of building it statically, we dynamically load the shared library at runtime.

## Building the Library

### Linux

```bash
# Build the shared library
cd hev-socks5-tunnel
make shared

# Copy to target directory
cp libhev-socks5-tunnel.so ../target/release/
```

### Windows

```bash
# Using MSYS2 or WSL
cd hev-socks5-tunnel
make shared

# Copy to target directory
cp hev-socks5-tunnel.dll ../target/release/
```

### Using the helper script

```bash
# Build and copy the library automatically
./scripts/build-hev-library.sh
```

## Loading the Library

The library is loaded dynamically at runtime from the following locations:

1. **Environment variable**: `HEV_SOCKS5_TUNNEL_LIB`
2. **Current executable directory**: Same folder as the aether binary
3. **System library paths**: `/usr/lib/`, `/usr/local/lib/`, etc.

### Setting the library path

```bash
# Linux
export HEV_SOCKS5_TUNNEL_LIB=/path/to/libhev-socks5-tunnel.so

# Windows (PowerShell)
$env:HEV_SOCKS5_TUNNEL_LIB="C:\path\to\hev-socks5-tunnel.dll"
```

## Distribution

For distribution, include the library in the same directory as the executable:

```
FCAE_VPN/
├── fcaevpn (or fcaevpn.exe)
├── libhev-socks5-tunnel.so (Linux)
├── hev-socks5-tunnel.dll (Windows)
└── config/
```

## Troubleshooting

### Library not found

```bash
# Check if library exists
ls -la libhev-socks5-tunnel.so

# Set environment variable
export HEV_SOCKS5_TUNNEL_LIB=$(pwd)/libhev-socks5-tunnel.so

# Run with LD_LIBRARY_PATH (Linux)
LD_LIBRARY_PATH=$(pwd) ./fcaevpn
```

### Missing symbols

Make sure you're using the correct version of hev-socks5-tunnel that exports:
- `hev_socks5_tunnel_main_from_str`
- `hev_socks5_tunnel_quit`
- `hev_socks5_tunnel_stats`

Check with:
```bash
nm -D libhev-socks5-tunnel.so | grep hev_socks5_tunnel
```

## Build Dependencies

The hev-socks5-tunnel library requires:
- `libevent` development headers
- `make`, `gcc`/`clang`

Install on Ubuntu:
```bash
sudo apt-get install build-essential libevent-dev
```

Install on Fedora:
```bash
sudo dnf install make gcc libevent-devel
```
