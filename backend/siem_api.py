from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


class AlertPayload(BaseModel):
    severity: str = Field(..., examples=["high", "critical"])
    source: str = "wazuh"
    alert: dict
    analysis: dict | None = None


class AlertRecord(AlertPayload):
    received_at: str


app = FastAPI(title="Cybervision SIEM API", version="0.1.0")

frontend_path = Path(__file__).resolve().parent.parent / "frontend"
if frontend_path.exists():
    app.mount("/ui", StaticFiles(directory=frontend_path, html=True), name="frontend")


def storage_path() -> Path:
    value = os.getenv("SIEM_STORAGE_PATH", "./data/siem-ingested.json")
    return Path(value)


def append_record(record: AlertRecord) -> None:
    path = storage_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(record.model_dump_json() + "\n")


def load_records(limit: int = 100) -> List[AlertRecord]:
    path = storage_path()
    if not path.exists():
        return []

    records: List[AlertRecord] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                data = json.loads(line)
                records.append(AlertRecord(**data))
            except json.JSONDecodeError:
                continue

    return records[-limit:]


@app.post("/api/v1/logs", response_model=AlertRecord)
def ingest_log(payload: AlertPayload) -> AlertRecord:
    if payload.severity not in {"high", "critical"}:
        raise HTTPException(status_code=400, detail="Only high and critical logs are accepted.")

    record = AlertRecord(
        **payload.model_dump(),
        received_at=datetime.now(timezone.utc).isoformat(),
    )
    append_record(record)
    return record


@app.get("/api/v1/logs", response_model=list[AlertRecord])
def list_logs(limit: int = 100) -> list[AlertRecord]:
    return load_records(limit)


@app.get("/api/v1/status")
def status() -> dict:
    return {"status": "ok", "records": len(load_records())}
