#!/usr/bin/env bash
set -euo pipefail

OUTPUT_PATH="${OUTPUT_PATH:-./data/generated-alerts.json}"
HOSTNAME_VALUE="${HOSTNAME_VALUE:-lab-agent-01}"

mkdir -p "$(dirname "$OUTPUT_PATH")"

random_level() {
  local levels=("3" "5" "7" "9" "10" "12" "14")
  echo "${levels[$((RANDOM % ${#levels[@]}))]}"
}

while true; do
  level="$(random_level)"
  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  rule_id="$((100000 + RANDOM % 900000))"
  description="Simulated Wazuh alert at level ${level}"

  cat <<EOF >> "$OUTPUT_PATH"
{"timestamp":"${timestamp}","rule":{"id":"${rule_id}","level":${level},"description":"${description}"},"agent":{"name":"${HOSTNAME_VALUE}"},"full_log":"Generated log entry level ${level}"}
EOF

  sleep 2
done
