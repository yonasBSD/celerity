# Performance Notes

This directory is for repeatable benchmark workflow around Celerity.

The benchmark binaries themselves stay in `src/bin/` so Cargo can build and run them normally:

- `local_lat`
- `remote_lat`
- `local_thr`
- `remote_thr`

## Goal

The point of these benchmarks is not to produce flattering numbers. The point is to make it easy to compare Celerity and libzmq under the same conditions.

For throughput, the intended comparison is:

- Celerity `local_thr` / `remote_thr`
- libzmq `local_thr` / `remote_thr`

For latency, the intended comparison is:

- Celerity `local_lat` / `remote_lat`
- libzmq `local_lat` / `remote_lat`

Run the receiver first, then the sender.

## Recommended Sizes

Use the same message count for each size unless you have a reason to change it.

- `1`
- `64`
- `256`
- `1024`
- `4096`
- `65536`

A reasonable default message count is `100000`.

## Celerity Throughput

Terminal 1:

```bash
cargo run --release --features tokio --bin local_thr -- tcp://127.0.0.1:5555 1024 100000
```

Terminal 2:

```bash
cargo run --release --features tokio --bin remote_thr -- tcp://127.0.0.1:5555 1024 100000
```

`local_thr` is the side that reports the benchmark result. `remote_thr` just pushes the traffic.

## Celerity Latency

Terminal 1:

```bash
cargo run --release --features tokio --bin local_lat -- tcp://127.0.0.1:5555 1024 100000
```

Terminal 2:

```bash
cargo run --release --features tokio --bin remote_lat -- tcp://127.0.0.1:5555 1024 100000
```

`remote_lat` is the side that reports the benchmark result. It performs one warmup round trip and then times the remaining request/reply loop.

## libzmq Throughput

Terminal 1:

```bash
./perf/local_thr tcp://127.0.0.1:5555 1024 100000
```

Terminal 2:

```bash
./perf/remote_thr tcp://127.0.0.1:5555 1024 100000
```

## Suggested Method

- Use `--release`.
- Run on the same machine for both Celerity and libzmq.
- Keep the endpoint, message size, and message count identical.
- Run each case at least 3 times.
- Compare median-to-median or best-of-3 to best-of-3, but stay consistent.
- Record the receiver-side throughput, not the sender-side timing.
- Record latency from the requester side, not the responder side.

## Result Template

### Throughput

| implementation | transport | size (bytes) | count | msg/s | MiB/s | notes |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| celerity | tcp loopback | 1024 | 100000 | | | |
| libzmq | tcp loopback | 1024 | 100000 | | | |

### Latency

| implementation | transport | size (bytes) | round trips | avg latency (us) | notes |
| --- | --- | ---: | ---: | ---: | --- |
| celerity | tcp loopback | 1024 | 100000 | | |
| libzmq | tcp loopback | 1024 | 100000 | | |

## Automation

There is a helper script in this directory:

```bash
./perf/run_thr.sh
```

It runs the Celerity throughput pair for the default size grid and prints a compact summary.

There is also a latency runner:

```bash
./perf/run_lat.sh
```
