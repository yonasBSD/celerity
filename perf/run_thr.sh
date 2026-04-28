#!/usr/bin/env bash
set -euo pipefail

endpoint="${ENDPOINT:-tcp://127.0.0.1:5555}"
count="${COUNT:-1000000}"

if (($# > 0)); then
  sizes=("$@")
else
  sizes=(1 64 256 1024 4096 65536)
fi

echo "Celerity throughput sweep"
echo "endpoint: ${endpoint}"
echo "message count: ${count}"
echo

cargo build --release --features tokio --bin local_thr --bin remote_thr >/dev/null

for size in "${sizes[@]}"; do
  echo "== size ${size} bytes =="

  local_log="$(mktemp)"
  target/release/local_thr "${endpoint}" "${size}" "${count}" >"${local_log}" 2>&1 &
  local_pid=$!

  sleep 0.2

  target/release/remote_thr "${endpoint}" "${size}" "${count}" >/dev/null

  wait "${local_pid}"
  grep -E '^(throughput|bandwidth):' "${local_log}"
  rm -f "${local_log}"
  echo
done
