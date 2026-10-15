import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from apps.api.app import main
from apps.api.app.database import initialize_schema
from apps.api.app.repository import EvidenceRepository

ROOT = Path(__file__).resolve().parents[3]
PRIMARY_FIXTURE = ROOT / "data" / "scenarios" / "primary-v1" / "events.jsonl"


def primary_events() -> list[dict]:
    return [json.loads(line) for line in PRIMARY_FIXTURE.read_text().splitlines() if line.strip()]


@pytest.fixture
def client(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    initialize_schema(engine)
    monkeypatch.setattr(main, "repository", EvidenceRepository(engine))
    with TestClient(main.app) as test_client:
        yield test_client


def ingest(client: TestClient, events: list[dict], key: str = "test-run") -> dict:
    response = client.post(
        "/api/v1/events/ingest",
        headers={"Idempotency-Key": key},
        json={"events": events},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_primary_fixture_materializes_expected_evidence_slice(client):
    result = ingest(client, primary_events(), "primary")

    assert result["accepted"] == 7
    assert result["rejected"] == 0
    assert result["duplicates"] == 0
    assert result["candidate_incident_ids"] == ["INC-PRIMARY-001"]

    events = client.get("/api/v1/events").json()
    assert events["total"] == 7
    first = events["items"][0]
    assert first["source_event_id"] == "AUTH-001"
    assert first["event_fingerprint"] == (
        "sha256-v1:48658aad4b1410b3157621cada55168a9e09390a3b6403ef2febcf1be5546fe2"
    )
    assert first["raw_event"] == primary_events()[0]
    assert first["normalized_fields"]["outcome"] == "failure"

    incident = client.get("/api/v1/incidents/INC-PRIMARY-001")
    assert incident.status_code == 200
    body = incident.json()
    assert body["incident"]["status"] == "investigating"
    assert [event["source_event_id"] for event in body["events"]] == [
        "AUTH-001",
        "AUTH-002",
        "AUTH-003",
        "AUTH-004",
        "SESSION-001",
        "PROC-001",
        "NET-001",
    ]
    assert [finding["rule_id"] for finding in body["findings"]] == [
        "AUTH-BURST-001",
        "AUTH-SUCCESS-AFTER-BURST-001",
        "PRIVILEGED-FOLLOW-ON-001",
    ]
    assert all(finding["rule_version"] == "1.0" for finding in body["findings"])
    assert body["findings"][0]["evidence_event_ids"]
    assert body["findings"][0]["evidence"] == ["AUTH-001", "AUTH-002", "AUTH-003"]
    assert body["incident"]["evidence"] == [
        "AUTH-001",
        "AUTH-002",
        "AUTH-003",
        "AUTH-004",
        "SESSION-001",
        "PROC-001",
        "NET-001",
    ]
    assert {entity["canonical_key"] for entity in body["entities"]} == {
        "user:alice",
        "ip:203.0.113.50",
        "host:ws-07",
        "session:session-S104",
        "process:powershell.exe",
        "ip:198.51.100.24",
    }
    graph = client.get("/api/v1/incidents/INC-PRIMARY-001/graph")
    assert graph.status_code == 200
    assert len(graph.json()["nodes"]) == 6
    assert graph.json()["edges"]
    assert all(edge["evidence_event_ids"] for edge in graph.json()["edges"])


def test_duplicate_fingerprint_is_suppressed_and_idempotency_replays_run(client):
    events = primary_events()
    first = ingest(client, events, "first")
    duplicate = ingest(client, events, "second")

    assert first["accepted"] == 7
    assert duplicate["accepted"] == 0
    assert duplicate["duplicates"] == 7
    assert client.get("/api/v1/events").json()["total"] == 7
    assert client.get("/api/v1/incidents").json()["total"] == 1

    replay = client.post(
        "/api/v1/events/ingest",
        headers={"Idempotency-Key": "first"},
        json={"events": []},
    )
    assert replay.status_code == 200
    assert replay.json() == first


def test_malformed_record_is_reported_without_aborting_valid_records(client):
    valid = primary_events()[0]
    malformed = [
        valid,
        {"source_type": "authentication", "event_type": "login_failure"},
        {
            **valid,
            "source_event_id": "BAD-IP",
            "source_ip": "not-an-ip",
        },
    ]

    result = ingest(client, malformed, "malformed")

    assert result["accepted"] == 1
    assert result["rejected"] == 2
    assert result["duplicates"] == 0
    assert len(result["errors"]) == 2
    assert all(error["code"] == "malformed_record" for error in result["errors"])
    stored_run = client.get(f"/api/v1/ingestion-runs/{result['run_id']}")
    assert stored_run.status_code == 200
    assert stored_run.json()["rejected"] == 2
    assert client.get("/api/v1/events").json()["total"] == 1


def test_out_of_order_submission_reconstructs_event_timeline(client):
    result = ingest(client, list(reversed(primary_events())), "out-of-order")

    assert result["accepted"] == 7
    timeline = client.get("/api/v1/incidents/INC-PRIMARY-001/timeline")
    assert timeline.status_code == 200
    assert [event["source_event_id"] for event in timeline.json()["items"]] == [
        "AUTH-001",
        "AUTH-002",
        "AUTH-003",
        "AUTH-004",
        "SESSION-001",
        "PROC-001",
        "NET-001",
    ]


def test_benign_unusual_login_is_stored_without_candidate_compromise(client):
    benign = [
        {
            "source_event_id": "BENIGN-001",
            "source_type": "authentication",
            "event_type": "login_success",
            "event_time": "2026-10-15T12:00:00-04:00",
            "username": "alice",
            "source_ip": "198.51.100.10",
            "outcome": "success",
        }
    ]

    result = ingest(client, benign, "benign")

    assert result["accepted"] == 1
    assert client.get("/api/v1/events").json()["items"][0]["event_time"] == "2026-10-15T16:00:00Z"
    assert client.get("/api/v1/incidents").json()["total"] == 0


def test_failed_login_burst_stays_a_low_confidence_signal_without_success(client):
    result = ingest(client, primary_events()[:3], "incomplete")

    assert result["accepted"] == 3
    incidents = client.get("/api/v1/incidents").json()
    assert incidents["total"] == 1
    incident_id = incidents["items"][0]["incident_id"]
    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["incident"]["confidence"] == "low"
    assert [finding["rule_id"] for finding in detail["findings"]] == ["AUTH-BURST-001"]
    assert detail["findings"][0]["evidence"] == ["AUTH-001", "AUTH-002", "AUTH-003"]


def test_jsonl_upload_keeps_record_level_failures(client):
    lines = "\n".join(
        [
            json.dumps(primary_events()[0]),
            "not-json",
            json.dumps(primary_events()[1]),
        ]
    )
    response = client.post(
        "/api/v1/events/upload",
        headers={"Idempotency-Key": "jsonl"},
        content=lines,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 2
    assert body["rejected"] == 1
    assert body["errors"][0]["record_number"] == 2
    assert body["errors"][0]["code"] == "invalid_json"
