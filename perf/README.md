# Performance Notes

This directory is for repeatable benchmark workflow around Celerity.

The benchmark binaries themselves stay in `src/bin/` so Cargo can build and run them normally:

- `local_thr`
- `remote_thr`

## Goal

The point of these benchmarks is not to produce flattering numbers. The point is to make it easy to compare Celerity and libzmq under the same conditions.

For throughput, the intended comparison is:

- Celerity `local_thr` / `remote_thr`
- libzmq `local_thr` / `remote_thr`

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

## Result Template

| implementation | transport | size (bytes) | count | msg/s | MiB/s | notes |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| celerity | tcp loopback | 1024 | 100000 | | | |
| libzmq | tcp loopback | 1024 | 100000 | | | |

## Automation

There is a helper script in this directory:

```bash
./perf/run_thr.sh
```

It runs the Celerity throughput pair for the default size grid and prints a compact summary.
