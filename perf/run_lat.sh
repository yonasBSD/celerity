#!/usr/bin/env bash
set -euo pipefail

endpoint="${ENDPOINT:-tcp://127.0.0.1:5555}"
count="${COUNT:-10000}"

if (($# > 0)); then
  sizes=("$@")
else
  sizes=(1 64 256 1024 4096 65536)
fi

echo "Celerity latency sweep"
echo "endpoint: ${endpoint}"
echo "roundtrip count: ${count}"
echo

cargo build --release --features tokio --bin local_lat --bin remote_lat >/dev/null

for size in "${sizes[@]}"; do
  echo "== size ${size} bytes =="

  local_log="$(mktemp)"
  target/release/local_lat "${endpoint}" "${size}" "${count}" >"${local_log}" 2>&1 &
  local_pid=$!

  sleep 0.2

  target/release/remote_lat "${endpoint}" "${size}" "${count}"

  wait "${local_pid}"
  rm -f "${local_log}"
  echo
done
