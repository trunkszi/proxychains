# Proxychains

Route TCP connections and DNS lookups of dynamically linked UNIX programs through SOCKS5, SOCKS4a, HTTP CONNECT, or RAW proxy chains via `LD_PRELOAD`.

## Build

Requires a C++23 compiler and [xmake](https://xmake.io). Dependencies (`fmt`, `fmtlog`, `glaze`, `c-ares`, `cxxopts`) are fetched automatically by `xmake`.

```bash
# Build shared library and CLI
xmake

# Build optional DNS daemon
xmake build proxychains-daemon

# Build and run tests
xmake build -g tests
xmake test

# Install (lib, bin, config, zsh & bash completions)
xmake install
```

## Usage

```bash
# Use default config file
proxychains curl https://example.com

# Direct single proxy without a config file
proxychains -p socks5://127.0.0.1:1080 curl https://example.com

# Custom config file and quiet mode
proxychains -q -f /path/to/proxychains.yaml curl https://example.com

# Spoof UID/GID
proxychains -u 0 id
proxychains -u 1000 -g 1000 whoami
```

### CLI Options

| Option | Description |
| --- | --- |
| `-q`, `--quiet` | Quiet mode |
| `-f`, `--file <path>` | Configuration file path |
| `-p`, `--proxy <url>` | Direct proxy URL (`socks5://`, `socks4://`, `http://`, `raw://`) |
| `-u`, `--uid <uid>` | Fake UID |
| `-g`, `--gid <gid>` | Fake GID (defaults to `-u` when omitted) |
| `-v`, `--version` | Show version |
| `-h`, `--help` | Show help |

### Environment Variables

| Variable | Description |
| --- | --- |
| `PROXYCHAINS_CONF_FILE` | Configuration file path |
| `PROXYCHAINS_PROXY_URL` | Direct proxy URL (`[scheme://][user:pass@]host:port`) |
| `PROXYCHAINS_QUIET_MODE` | Set `1` to enable quiet mode |
| `PROXYCHAINS_FAKE_UID` | Fake UID |
| `PROXYCHAINS_FAKE_GID` | Fake GID |

## Configuration (`proxychains.yaml`)

Search order: `-f` / `PROXYCHAINS_CONF_FILE` $\rightarrow$ `./proxychains.yaml` $\rightarrow$ `~/.proxychains/proxychains.yaml` $\rightarrow$ `/usr/local/etc/proxychains.yaml` $\rightarrow$ `/etc/proxychains.yaml`.

```yaml
chain_type: dynamic          # dynamic, strict, random, round_robin
# chain_len: 2               # hop count for random / round_robin
quiet_mode: false

dns:
  method: thread             # thread, daemon, or off
  remote_subnet: 224
  daemon_addr: "127.0.0.1:1053"

timeouts:
  tcp_read_ms: 15000
  tcp_connect_ms: 8000

localnet:
  - "127.0.0.0/8"
  - "192.168.0.0/16"
  - "[::1]/128"

# dnat:
#   - orig: "1.1.1.1:1234"
#     new: "1.1.1.2:443"

proxies:
  - type: socks5
    host: "127.0.0.1"
    port: 1080
    user: "username"         # optional
    pass: "password"         # optional
```
