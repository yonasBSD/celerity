#!/usr/bin/env bash
set -euo pipefail

endpoint="${ENDPOINT:-tcp://127.0.0.1:5555}"
count="${COUNT:-1000000}"
csv_path="${CSV_PATH:-perf/celerity_thr_results.csv}"

if (($# > 0)); then
  sizes=("$@")
else
  sizes=(1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768 65536)
fi

echo "Celerity throughput sweep"
echo "endpoint: ${endpoint}"
echo "message count: ${count}"
echo "csv: ${csv_path}"
echo

cargo build --release --features tokio --bin local_thr --bin remote_thr >/dev/null

printf 'message_size,message_count,msg_per_s,mib_per_s\n' >"${csv_path}"

for size in "${sizes[@]}"; do
  echo "== size ${size} bytes =="

  local_log="$(mktemp)"
  target/release/local_thr "${endpoint}" "${size}" "${count}" >"${local_log}" 2>&1 &
  local_pid=$!

  sleep 0.2

  target/release/remote_thr "${endpoint}" "${size}" "${count}" >/dev/null

  wait "${local_pid}"
  grep -E '^(throughput|bandwidth):' "${local_log}"
  throughput="$(awk '/^throughput:/ {print $2}' "${local_log}")"
  bandwidth="$(awk '/^bandwidth:/ {print $2}' "${local_log}")"
  printf '%s,%s,%s,%s\n' "${size}" "${count}" "${throughput}" "${bandwidth}" >>"${csv_path}"
  rm -f "${local_log}"
  echo
done
