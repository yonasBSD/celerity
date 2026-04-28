#!/usr/bin/env bash
set -euo pipefail

endpoint="${ENDPOINT:-tcp://127.0.0.1:5555}"
count="${COUNT:-10000}"
csv_path="${CSV_PATH:-perf/celerity_lat_results.csv}"

if (($# > 0)); then
  sizes=("$@")
else
  sizes=(1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768 65536)
fi

echo "Celerity latency sweep"
echo "endpoint: ${endpoint}"
echo "roundtrip count: ${count}"
echo "csv: ${csv_path}"
echo

cargo build --release --features tokio --bin local_lat --bin remote_lat >/dev/null

printf 'message_size,roundtrip_count,avg_latency_us\n' >"${csv_path}"

for size in "${sizes[@]}"; do
  echo "== size ${size} bytes =="

  local_log="$(mktemp)"
  target/release/local_lat "${endpoint}" "${size}" "${count}" >"${local_log}" 2>&1 &
  local_pid=$!

  sleep 0.2

  remote_log="$(mktemp)"
  target/release/remote_lat "${endpoint}" "${size}" "${count}" | tee "${remote_log}"
  latency="$(awk '/^average latency:/ {print $3}' "${remote_log}")"
  printf '%s,%s,%s\n' "${size}" "${count}" "${latency}" >>"${csv_path}"

  wait "${local_pid}"
  rm -f "${remote_log}"
  rm -f "${local_log}"
  echo
done
