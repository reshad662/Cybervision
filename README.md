# Cybervision Wazuh → Gemini → SIEM Pipeline

Bu repoda Wazuh loglarinin avtomatik yigimi, Gemini AI analizi ve SIEM API-si ile inteqrasiya ucun minimum isleyen sistem var.

## Konfiqurasiya

`config.yaml` faylinda Wazuh server IP-si ve log fayl yollarini deyise bilersiniz.

```yaml
wazuh:
  server_ip: "192.168.0.114"
```

## Log generator (Bash)

```bash
chmod +x scripts/generate_logs.sh
OUTPUT_PATH=./data/generated-alerts.json ./scripts/generate_logs.sh
```

Bu script Wazuh formatina benzeyen JSON loglari yaradir.

## Log yoxlama (Python)

```bash
python3 scripts/check_wazuh_logs.py --config config.yaml
```

Script her 60 saniyede bir log faylini oxuyur, `high` ve `critical` seviyeleri secir,
Gemini ile analiz edir (GEMINI_API_KEY varsa) ve SIEM API-ya gonderir.

## SIEM API (FastAPI)

```bash
pip install -r requirements.txt
uvicorn backend.siem_api:app --host 0.0.0.0 --port 8000
```

API endpointleri:

- `POST /api/v1/logs` — high/critical log qebulu
- `GET /api/v1/logs` — son loglarin siyahisi
- `GET /api/v1/status` — status
- `GET /ui` — SIEM dashboard (frontend)

## Gemmini AI (Gemini)

Gemini inteqrasiyasi ucun `GEMINI_API_KEY` env dəyeri verin:

```bash
export GEMINI_API_KEY="your-key"
```
