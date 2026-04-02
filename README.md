# Celerity

Celerity is a pure Rust implementation of ZMTP 3.1 built around a sans-IO core. The protocol engine stays as a state machine, while the Tokio layer handles TCP and Unix domain socket transport for practical use.

The project is aimed at people who want a small, direct Rust messaging stack without pulling in a C library or hiding the wire protocol behind too much magic.

## What It Includes

- ZMTP 3.1 greeting, handshake, framing, and multipart message handling
- Sans-IO `CelerityPeer` core
- Tokio transport wrappers for TCP and IPC on Unix
- `PUB/SUB` and `REQ/REP` helpers
- CURVE-RS encrypted transport mode for non-local links
- `cel-cat` CLI for quick local testing

## Install

### Build the library

```bash
cargo build
```

### Install the CLI from source

```bash
cargo install --path . --features cli --bin cel-cat
```

### Run the full test suite

```bash
cargo test --all-features
```

## Feature Flags

- `tokio`: enables the Tokio transport layer
- `cli`: builds the `cel-cat` utility
- `ipc`: enables Unix domain socket support
- `curve`: enables CURVE-RS security

For day-to-day local testing, `--all-features` is the simplest path.

## CLI Quick Start

### Local TCP on one machine

Terminal 1:

```bash
cargo run --all-features --bin cel-cat -- sub 127.0.0.1:5555
```

Terminal 2:

```bash
cargo run --all-features --bin cel-cat -- pub 127.0.0.1:5555 hello from tcp
```

### TCP between your host and a VM on the same network

This is still TCP. It is the right transport when your host machine and a VM need to talk over a real IP address on the same LAN, bridged adapter, or host-only network.

Example with the host publishing and the VM subscribing:

On your host Mac:

```bash
cargo run --all-features --bin cel-cat -- pub 0.0.0.0:5555 hello from host
```

On your Kali VM:

```bash
cargo run --all-features --bin cel-cat -- sub <HOST-IP>:5555
```

Example with the VM publishing and the host subscribing:

On your Kali VM:

```bash
cargo run --all-features --bin cel-cat -- pub 0.0.0.0:5555 hello from kali
```

On your host Mac:

```bash
cargo run --all-features --bin cel-cat -- sub <VM-IP>:5555
```

### IPC on the same machine

`ipc://` uses Unix domain sockets, so both processes must run on the same machine.

Terminal 1:

```bash
cargo run --all-features --bin cel-cat -- sub ipc:///tmp/celerity.sock
```

Terminal 2:

```bash
cargo run --all-features --bin cel-cat -- pub ipc:///tmp/celerity.sock hello from ipc
```

### Multi-word messages

`cel-cat pub` accepts trailing words as one message, so this works as expected:

```bash
cargo run --all-features --bin cel-cat -- pub 127.0.0.1:5555 hello there world
```

## Local, IPC, and Remote Use

### Loopback TCP

`127.0.0.1` and `localhost` are treated as local links. That means `NULL` security is allowed by default for quick development and local testing.

### IPC

IPC is local-only. It does not travel over Wi-Fi, Ethernet, or between separate VMs. It is the fastest and simplest option when both processes live on the same host.

### Remote TCP

For non-loopback TCP, the intended path is CURVE-RS. The library defaults to failing closed for remote `NULL` unless you explicitly opt into insecure mode.

The high-level CLI is meant for local workflows first. For remote hosts, use the library API with an explicit `SecurityConfig::curve()` setup and managed key material.

That means host-to-VM traffic over a real IP is TCP, but it is no longer treated as a local loopback link. If you want that path to be secure and reliable beyond local experiments, use CURVE-RS through the library API rather than relying on plain `NULL`.

## Using It As a Library

Add the crate with the feature set you need:

```toml
[dependencies]
celerity = { version = "0.1.0", features = ["tokio", "ipc", "curve"] }
```

At the core is `CelerityPeer`, which owns protocol state but no sockets. The Tokio wrappers in `celerity::io` sit on top when you want real network transport.

## Project Layout

- `src/lib.rs`: public API and shared protocol types
- `src/peer.rs`: sans-IO ZMTP peer state machine
- `src/pattern.rs`: `PUB/SUB` and `REQ/REP` coordinators
- `src/io/`: Tokio transport, endpoint parsing, and socket wrappers
- `src/security/`: NULL and CURVE-RS mechanisms
- `src/bin/cel_cat.rs`: small CLI for interactive testing

## Development

Format and test before pushing:

```bash
cargo fmt
cargo test
cargo test --all-features
```

## Release Notes

For the initial release:

```bash
git tag -a v0.1.0 -m "Initial release with IPC and CURVE"
git push origin v0.1.0
```

## License

Licensed under either:

- MIT
- Apache-2.0
