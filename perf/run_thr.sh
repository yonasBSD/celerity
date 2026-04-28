#!/usr/bin/env bash
set -euo pipefail

endpoint="${ENDPOINT:-tcp://127.0.0.1:5555}"
count="${COUNT:-100000}"
sizes=("${@:-1 64 256 1024 4096 65536}")

echo "Celerity throughput sweep"
echo "endpoint: ${endpoint}"
echo "message count: ${count}"
echo

for size in "${sizes[@]}"; do
  echo "== size ${size} bytes =="

  local_log="$(mktemp)"
  cargo run --release --features tokio --bin local_thr -- "${endpoint}" "${size}" "${count}" \
    >"${local_log}" 2>&1 &
  local_pid=$!

  sleep 0.2

  cargo run --release --features tokio --bin remote_thr -- "${endpoint}" "${size}" "${count}" >/dev/null

  wait "${local_pid}"
  grep -E '^(throughput|bandwidth):' "${local_log}"
  rm -f "${local_log}"
  echo
done
