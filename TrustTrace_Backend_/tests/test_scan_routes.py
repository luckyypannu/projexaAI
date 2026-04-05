"""
tests/test_scan_routes.py

Integration tests for /scan, /report, /health endpoints.

CHANGES:
  [1] _make_clean_api() mock uses urlhaus key instead of phishtank.
  [2] pattern_flags added to required response keys assertion.
  [3] Mock target updated from asyncio.run to _run_async.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture()
def app():
    import database.mongo_connection as mongo_mod

    mock_col = MagicMock()
    mock_col.find_one.return_value = None
    mock_col.count_documents.return_value = 0
    mock_col.update_one.return_value = None

    mock_db = MagicMock()
    mock_db.__getitem__.return_value = mock_col

    mock_client = MagicMock()
    mock_client.get_default_database.return_value = mock_db

    with patch.object(mongo_mod, "MongoClient", return_value=mock_client), \
         patch.object(mongo_mod, "_db", mock_db), \
         patch("ingestion.scam_data_fetcher.start_scheduler"):
        from app import create_app
        application = create_app()
        application.config["TESTING"] = True
        yield application


@pytest.fixture()
def client(app):
    return app.test_client()


# ── /health ────────────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"


# ── /scan validation ───────────────────────────────────────────────────────────

class TestScanValidation:
    def test_missing_body_returns_400(self, client):
        resp = client.post("/scan", content_type="application/json", data="{}")
        assert resp.status_code == 400

    def test_empty_input_returns_400(self, client):
        resp = client.post("/scan", json={"input": "   "})
        assert resp.status_code == 400

    def test_no_json_returns_400(self, client):
        resp = client.post("/scan", data="not json", content_type="text/plain")
        assert resp.status_code == 400


# ── /scan success paths ────────────────────────────────────────────────────────

class TestScanSuccess:

    def _post_scan(self, client, input_value: str):
        return client.post("/scan", json={"input": input_value})

    @patch("routes.scan_routes._run_async")
    @patch("routes.scan_routes.get_collection")
    def test_url_scan_returns_correct_shape(self, mock_get_col, mock_run, client):
        """Response must contain all six required keys including pattern_flags."""
        mock_col = MagicMock()
        mock_col.find_one.return_value = None
        mock_col.count_documents.return_value = 0
        mock_col.update_one.return_value = None
        mock_get_col.return_value = mock_col
        # URLhaus clean response
        mock_run.return_value = {
            "urlhaus": {"found": False, "url_status": "", "threat": "", "tags": [], "query_status": "no_results"}
        }

        resp = self._post_scan(client, "http://example.com")
        assert resp.status_code == 200
        data = resp.get_json()
        for key in ("input", "type", "trust_score", "risk_level", "advice", "pattern_flags"):
            assert key in data, f"Key '{key}' missing from response"

    @patch("routes.scan_routes._run_async")
    @patch("routes.scan_routes.get_collection")
    def test_score_within_range(self, mock_get_col, mock_run, client):
        mock_col = MagicMock()
        mock_col.find_one.return_value = None
        mock_col.count_documents.return_value = 0
        mock_col.update_one.return_value = None
        mock_get_col.return_value = mock_col
        mock_run.return_value = {}

        resp = self._post_scan(client, "https://google.com")
        data = resp.get_json()
        assert 0 <= data["trust_score"] <= 100

    @patch("routes.scan_routes._run_async")
    @patch("routes.scan_routes.get_collection")
    def test_risk_level_valid_value(self, mock_get_col, mock_run, client):
        mock_col = MagicMock()
        mock_col.find_one.return_value = None
        mock_col.count_documents.return_value = 0
        mock_col.update_one.return_value = None
        mock_get_col.return_value = mock_col
        mock_run.return_value = {}

        resp = self._post_scan(client, "http://paypa1.xyz/login")
        data = resp.get_json()
        assert data["risk_level"] in ("Low", "Medium", "High")

    @patch("routes.scan_routes.get_collection")
    def test_cache_hit_returns_immediately(self, mock_get_col, client):
        cached_doc = {
            "input": "http://cached.com",
            "type": "url",
            "trust_score": 90,
            "risk_level": "Low",
            "api_results": {},
            "pattern_flags": [],
            "advice": ["No major threats detected."],
            "timestamp": "2024-01-01T00:00:00+00:00",
        }
        mock_col = MagicMock()
        mock_col.find_one.return_value = cached_doc
        mock_get_col.return_value = mock_col

        with patch("routes.scan_routes._run_async") as mock_run:
            resp = self._post_scan(client, "http://cached.com")
            mock_run.assert_not_called()

        assert resp.status_code == 200

    @patch("routes.scan_routes._run_async")
    @patch("routes.scan_routes.get_collection")
    def test_pattern_flags_is_list(self, mock_get_col, mock_run, client):
        mock_col = MagicMock()
        mock_col.find_one.return_value = None
        mock_col.count_documents.return_value = 0
        mock_col.update_one.return_value = None
        mock_get_col.return_value = mock_col
        mock_run.return_value = {}

        resp = self._post_scan(client, "http://example.com")
        data = resp.get_json()
        assert isinstance(data["pattern_flags"], list)


# ── /report ────────────────────────────────────────────────────────────────────

class TestReportEndpoint:

    @patch("routes.scan_routes.get_collection")
    def test_report_submission_returns_201(self, mock_get_col, client):
        mock_col = MagicMock()
        mock_col.insert_one.return_value = None
        mock_get_col.return_value = mock_col

        resp = client.post(
            "/report",
            json={"input": "+2348012345678", "reason": "Scam call"},
        )
        assert resp.status_code == 201
        assert "message" in resp.get_json()

    def test_report_missing_input_returns_400(self, client):
        resp = client.post("/report", json={"reason": "no input given"})
        assert resp.status_code == 400
