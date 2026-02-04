#!/usr/bin/env python3
import argparse
import json
import os
import time
from dataclasses import dataclass
from typing import Dict, Iterable, Optional

import requests


@dataclass
class PipelineConfig:
    alerts_log_path: str
    output_filtered_path: str
    poll_interval_seconds: int
    high_level: int
    critical_level: int
    api_base_url: str
    ingest_endpoint: str


def load_config(path: str) -> PipelineConfig:
    import yaml

    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    return PipelineConfig(
        alerts_log_path=data["wazuh"]["alerts_log_path"],
        output_filtered_path=data["pipeline"]["output_filtered_path"],
        poll_interval_seconds=int(data["pipeline"]["poll_interval_seconds"]),
        high_level=int(data["pipeline"]["severity_levels"]["high"]),
        critical_level=int(data["pipeline"]["severity_levels"]["critical"]),
        api_base_url=data["siem"]["api_base_url"],
        ingest_endpoint=data["siem"]["ingest_endpoint"],
    )


def iter_new_lines(path: str, last_position: int) -> Iterable[str]:
    with open(path, "r", encoding="utf-8") as handle:
        handle.seek(last_position)
        for line in handle:
            yield line.strip()
        yield handle.tell()


def parse_alert(line: str) -> Optional[Dict]:
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def classify_alert(alert: Dict, high_level: int, critical_level: int) -> Optional[str]:
    level = int(alert.get("rule", {}).get("level", 0))
    if level >= critical_level:
        return "critical"
    if level >= high_level:
        return "high"
    return None


def send_to_siem(api_base_url: str, ingest_endpoint: str, payload: Dict) -> None:
    url = f"{api_base_url.rstrip('/')}{ingest_endpoint}"
    response = requests.post(url, json=payload, timeout=10)
    response.raise_for_status()


def analyze_with_gemini(alert: Dict) -> Dict:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {"analysis": "Gemini API key not configured; using rule-based severity.", "model": "local"}

    try:
        import google.generativeai as genai

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        prompt = (
            "Analyze the Wazuh alert JSON and return a short risk summary with severity"
            " (critical, high, medium, low). Alert JSON:\n"
            f"{json.dumps(alert)}"
        )
        response = model.generate_content(prompt)
        return {"analysis": response.text, "model": "gemini-1.5-flash"}
    except Exception as exc:  # noqa: BLE001 - capture any API errors to keep pipeline running
        return {"analysis": f"Gemini analysis failed: {exc}", "model": "fallback"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Poll Wazuh alerts file and forward high/critical alerts.")
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    config = load_config(args.config)
    os.makedirs(os.path.dirname(config.output_filtered_path), exist_ok=True)

    last_position = 0
    while True:
        if not os.path.exists(config.alerts_log_path):
            time.sleep(config.poll_interval_seconds)
            continue

        for line in iter_new_lines(config.alerts_log_path, last_position):
            if isinstance(line, int):
                last_position = line
                continue

            alert = parse_alert(line)
            if not alert:
                continue

            severity = classify_alert(alert, config.high_level, config.critical_level)
            if not severity:
                continue

            gemini_result = analyze_with_gemini(alert)
            payload = {
                "severity": severity,
                "source": "wazuh",
                "alert": alert,
                "analysis": gemini_result,
            }

            with open(config.output_filtered_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload) + "\n")

            send_to_siem(config.api_base_url, config.ingest_endpoint, payload)

        time.sleep(config.poll_interval_seconds)


if __name__ == "__main__":
    main()
