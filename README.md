# netprobe

[![C](https://img.shields.io/badge/C-11-00599C?logo=c)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-lightgrey)](#build)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](#why)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](#license)

A small, dependency-free multithreaded TCP port scanner written in plain C
(POSIX sockets + pthreads). No libpcap, no OpenSSL, no external libraries —
just `gcc` and a Makefile.

> **Only scan hosts and networks you own or have explicit permission to
> test.** Scanning systems without authorization may be illegal in your
> jurisdiction (in Ukraine: Art. 361 of the Criminal Code; similar laws
> exist almost everywhere). This tool is meant for auditing your own home
> lab, servers, or infrastructure you're responsible for.

```
$ ./netprobe -H 192.168.1.1 -p 1-1024 -t 100
netprobe: scanning 192.168.1.1 (1024 ports, 100 threads) -- only scan authorized targets
PORT     STATE    SERVICE          BANNER
22       open     ssh              SSH-2.0-OpenSSH_9.6p1
80       open     http
443      open     https
netprobe: done in 1.8s -- 3/1024 ports open
```

## Why

Most "port scanner in C" examples floating around online are either
single-threaded toy code or thin nmap wrappers. `netprobe` is a small,
readable, actually-multithreaded implementation you can drop into a home
lab or a small ops toolkit and read top to bottom in twenty minutes.

## Features

- **Multithreaded TCP connect scan** with a configurable thread pool
- **Non-blocking connect with timeout** (via `poll`), so a single
  filtered/dropped port doesn't stall the whole scan
- **Best-effort banner grabbing** — reads what the service says first,
  and nudges common HTTP-ish ports with a minimal `HEAD` request if silent
- **Flexible port specs**: `22`, `1-1024`, `20-25,80,443,8000-8100`
- **Known-service name lookup** for common ports (ssh, http, mysql, redis,
  rdp, mongodb, kubernetes-api, ...)
- **Output formats**: text (table), CSV, JSON
- Zero external dependencies — just libc and pthreads

## Build

```bash
make          # builds ./netprobe
make test     # runs the unit tests for port-list parsing
make clean
```

Requires a POSIX system (Linux, macOS, WSL) and a C11 compiler.

## Usage

```
netprobe -H <host> -p <ports> [options]

Required:
  -H, --host <host>          Target hostname or IP address
  -p, --ports <spec>         e.g. "22,80,443" or "1-1024" or "20-25,80,8000-8100"

Options:
  -t, --threads <n>          Worker threads (default: 50)
  -w, --timeout <ms>         Connect timeout in ms (default: 800)
  -b, --banner-timeout <ms>  Banner read timeout in ms (default: 500)
  -n, --no-banner            Skip banner grabbing (faster, connect-only)
  -a, --all                  Also print closed/filtered ports
  -o, --output <fmt>         text | csv | json (default: text)
  -h, --help                 Show help
```

### Examples

```bash
# Quick sweep of common ports on your own machine
./netprobe -H 127.0.0.1 -p 20-25,80,443,3306,5432,6379,8080

# Full range scan of a home router you administer, more threads for speed
./netprobe -H 192.168.1.1 -p 1-65535 -t 300 -o json > scan.json

# Fast connect-only scan (no banner grabbing) for a quick "what's open" check
./netprobe -H 10.0.0.5 -p 1-1024 -n
```

## How it works

Each worker thread pulls the next port off a shared, mutex-protected
counter and does a non-blocking `connect()`, waiting on `poll()` up to the
configured timeout. If the connection succeeds, the port is marked open
and (unless `-n` is set) the thread tries a short `recv()` to capture
whatever banner the service offers, nudging with a bare `HEAD / HTTP/1.0`
request for common HTTP-ish ports that stay silent until spoken to.

This is a **TCP connect scan** (like `nmap -sT`), not a raw-socket SYN
scan — it doesn't need root privileges and is friendlier to run from a
regular user account, at the cost of being slightly more visible in logs
than a stealth scan.

## Project layout

```
src/
  main.c       CLI argument parsing and orchestration
  scanner.c/h  connect + banner-grab logic, thread pool
  portlist.c/h port-spec parsing, known-service name table
  output.c/h   text / CSV / JSON formatting
tests/
  test_portlist.c   unit tests for port-spec parsing
```

## Tested with

Compiled with `-Wall -Wextra -std=c11`, zero warnings. Checked for memory
leaks with `valgrind --leak-check=full` (clean).

## License

MIT
