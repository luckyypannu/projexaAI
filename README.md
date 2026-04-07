# TrustTrace Backend

A production-grade Flask + MongoDB backend for the TrustTrace URL/phone/email
reputation scoring application.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Folder Structure](#folder-structure)
3. [Setup & Installation](#setup--installation)
4. [Configuration](#configuration)
5. [API Reference](#api-reference)
6. [Scoring Logic](#scoring-logic)
7. [Background Ingestion](#background-ingestion)
8. [Running in Production](#running-in-production)
9. [Running Tests](#running-tests)

---

## Architecture Overview

```
Frontend  ──POST /scan──►  Flask Route
                               │
                    ┌──────────▼──────────┐
                    │   MongoDB Cache?     │ ──YES──► Return cached result
                    └──────────┬──────────┘
                               │ NO
                    ┌──────────▼──────────┐
                    │  Async API Checks    │  ← asyncio.gather()
                    │  ┌───────────────┐  │
                    │  │ Google SafeBr │  │
                    │  │ URLhaus       │  │
                    │  │ VirusTotal    │  │
                    │  │ NumVerify     │  │
                    │  └───────────────┘  │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Pattern Detection   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Trust Score Engine  │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Advice Generator    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Save to MongoDB     │
                    └──────────┬──────────┘
                               │
                           Response
```

---

## Folder Structure

```
TrustTrace_Backend/
├── app.py                        # Application factory & entry point
├── config.py                     # All config from environment variables
├── requirements.txt
├── .env.example                  # Template — copy to .env
│
├── routes/
│   └── scan_routes.py            # /scan, /report, /health endpoints
│
├── services/
│   ├── async_api_checker.py      # Parallel external API calls
│   ├── pattern_detector.py       # Heuristic rule engine
│   ├── trust_score_engine.py     # Score calculation & risk banding
│   └── advice_generator.py       # Contextual advice messages
│
├── database/
│   └── mongo_connection.py       # MongoClient + index provisioning
│
├── models/
│   └── scan_model.py             # ScanResult dataclass + serialisation
│
├── ingestion/
│   └── scam_data_fetcher.py      # 24h background APScheduler job
│
├── utils/
│   └── __init__.py               # Shared helpers
│
└── tests/
    ├── test_pattern_detector.py
    ├── test_trust_score_engine.py
    ├── test_advice_generator.py
    └── test_scan_routes.py
```

---

## Setup & Installation

### Prerequisites

- Python 3.11+
- MongoDB 6.0+ (local or Atlas)

### Steps

```bash
# 1. Create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment variables
copy .env.example .env
# Open .env and add your API keys

# 4. Run the development server
python app.py
```

The server starts on **http://localhost:5000**.

---

## Configuration

| Variable | Description | Default |
|---|---|---|
| `FLASK_DEBUG` | Enable debug mode | `false` |
| `SECRET_KEY` | Flask secret key | `change-me` |
| `CORS_ORIGINS` | Allowed frontend origins | `*` |
| `MONGO_URI` | MongoDB connection string | `mongodb://localhost:27017/cybertrust` |
| `CACHE_TTL_SECONDS` | How long to cache scan results | `86400` (24h) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing API v4 key | — |
| `URLHAUS_API_KEY` | URLhaus (abuse.ch) API key | — |
| `VIRUSTOTAL_API_KEY` | VirusTotal API v3 key | — |
| `NUMVERIFY_API_KEY` | NumVerify phone validation key | — |
| `INGESTION_INTERVAL_HOURS` | Scam feed refresh interval | `24` |

---

## API Reference

### `POST /scan`

**Request**
```json
{ "input": "http://paypa1-secure.xyz/login" }
```

**Response `200 OK`**
```json
{
  "input": "http://paypa1-secure.xyz/login",
  "type": "url",
  "trust_score": 15,
  "risk_level": "High",
  "advice": ["Close this website immediately..."],
  "pattern_flags": ["Suspicious top-level domain: .xyz"]
}
```

---

### `POST /report`

**Request**
```json
{ "input": "+2348012345678", "reason": "Scam call" }
```

**Response `201 Created`**
```json
{ "message": "Report submitted. Thank you for helping keep the web safe." }
```

---

### `GET /health`

**Response `200 OK`**
```json
{ "status": "ok" }
```

---

## Scoring Logic

Every input starts at **100**. Deductions applied:

| Trigger | Points deducted |
|---|---|
| Google Safe Browsing flag | −50 |
| URLhaus database hit | −40 |
| URLhaus URL currently online | −10 |
| VirusTotal ≥3 malicious engines | −30 |
| VirusTotal 1–2 malicious engines | −15 |
| VirusTotal suspicious detections | −10 |
| Known-scam database hit | −50 |
| Suspicious TLD (.xyz, .tk, etc.) | −15 |
| Brand impersonation / typosquat | −20 |
| Phishing keyword in URL | −15 |
| Raw IP address as hostname | −15 |
| Unencrypted HTTP + sensitive keyword | −10 |
| VOIP phone number | −20 |
| Unknown carrier | −10 |
| High-risk country code | −20 |
| Invalid phone format | −60 |
| Email domain impersonation | −20 |

| Score range | Risk level |
|---|---|
| 80–100 | 🟢 Low |
| 50–79 | 🟡 Medium |
| 0–49 | 🔴 High |

---

## Background Ingestion

On startup and every 24 hours the scheduler fetches the OpenPhish feed
and upserts into the `known_scams` MongoDB collection automatically.

---

## Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

---

## Running with Docker

```bash
docker-compose up --build
```
