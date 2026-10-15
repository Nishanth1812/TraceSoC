import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, update
from sqlalchemy.pool import StaticPool

from apps.api.app import main
from apps.api.app.database import initialize_schema
from apps.api.app.investigation_service import InvestigationService
from apps.api.app.repository import EvidenceRepository
from apps.api.app.response_service import ResponseService
from apps.api.app.schema import simulated_state

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
    monkeypatch.setattr(main, "investigations", InvestigationService(engine))
    monkeypatch.setattr(main, "responses", ResponseService(engine))
    with TestClient(main.app) as test_client:
        yield test_client, engine


def ingest_primary(client: TestClient) -> dict:
    response = client.post(
        "/api/v1/events/ingest",
        headers={"Idempotency-Key": "investigation-response-primary"},
        json={"events": primary_events()},
    )
    assert response.status_code == 200, response.text
    return response.json()


def action_payload() -> dict:
    return {
        "action_type": "revoke_session",
        "target_session_id": "session-S104",
        "evidence_event_ids": ["SESSION-001", "PROC-001"],
        "rationale": "Revoke the simulated session while preserving the evidence trail.",
        "risk": "Low: one simulated session is affected.",
        "expected_outcome": "The session is no longer active.",
        "operational_impact": "Alice must authenticate again in the simulation.",
        "preconditions": ["The target session is active."],
        "rollback_plan": "Reset the local scenario state.",
        "verification_method": "Read simulated_state after execution.",
    }


def test_mock_investigation_is_evidence_cited_and_audited(client):
    api, _ = client
    ingest_primary(api)

    response = api.post(
        "/api/v1/incidents/INC-PRIMARY-001/investigations",
        json={"provider": "mock"},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["tool_call_count"] >= 3
    assert body["result"]["referenced_event_ids"]
    assert all(item["evidence_event_ids"] for item in body["result"]["observed_facts"])

    run = api.get(f"/api/v1/investigations/{body['run_id']}")
    assert run.status_code == 200
    audit = api.get("/api/v1/incidents/INC-PRIMARY-001/audit")
    assert audit.status_code == 200
    assert {item["event_type"] for item in audit.json()["items"]} >= {
        "investigation_started",
        "investigation_completed",
    }


def test_provider_failure_is_contained_without_losing_incident_evidence(client):
    api, _ = client
    ingest_primary(api)

    response = api.post(
        "/api/v1/incidents/INC-PRIMARY-001/investigations",
        json={"provider": "failing"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "failed"
    assert body["error"]["code"] == "provider_failure"
    assert api.get("/api/v1/incidents/INC-PRIMARY-001").status_code == 200


def test_response_requires_approval_and_verifies_simulated_state(client):
    api, _ = client
    ingest_primary(api)

    proposal = api.post(
        "/api/v1/incidents/INC-PRIMARY-001/response-plans",
        json=action_payload(),
    )
    assert proposal.status_code == 200, proposal.text
    action = proposal.json()
    assert action["status"] == "awaiting_approval"
    action_id = action["action_id"]

    blocked = api.post(
        f"/api/v1/response-actions/{action_id}/execute",
        headers={"Idempotency-Key": "blocked-before-approval"},
        json={},
    )
    assert blocked.status_code == 409
    assert blocked.json()["code"] == "action_not_approved"

    approved = api.post(f"/api/v1/response-actions/{action_id}/approve", json={})
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"

    executed = api.post(
        f"/api/v1/response-actions/{action_id}/execute",
        headers={"Idempotency-Key": "execute-primary"},
        json={},
    )
    assert executed.status_code == 200
    assert executed.json()["status"] == "succeeded"

    replay = api.post(
        f"/api/v1/response-actions/{action_id}/execute",
        headers={"Idempotency-Key": "execute-primary"},
        json={},
    )
    assert replay.status_code == 200
    assert replay.json()["action_id"] == action_id

    verification = api.get(f"/api/v1/response-actions/{action_id}/verification")
    assert verification.status_code == 200
    assert verification.json()["status"] == "verified"
    assert api.get("/api/v1/incidents/INC-PRIMARY-001").json()["incident"]["status"] == "contained"


def test_failed_verification_reopens_investigation(client):
    api, engine = client
    ingest_primary(api)
    proposal = api.post(
        "/api/v1/incidents/INC-PRIMARY-001/response-plans",
        json=action_payload(),
    ).json()
    action_id = proposal["action_id"]
    api.post(f"/api/v1/response-actions/{action_id}/approve", json={})
    api.post(
        f"/api/v1/response-actions/{action_id}/execute",
        headers={"Idempotency-Key": "execute-failure-path"},
        json={},
    )

    with engine.begin() as connection:
        connection.execute(
            update(simulated_state)
            .where(simulated_state.c.session_id == "session-S104")
            .values(
                active=True, state_json=json.dumps({"active": True, "session_id": "session-S104"})
            )
        )

    verification = api.get(f"/api/v1/response-actions/{action_id}/verification")
    assert verification.status_code == 200
    assert verification.json()["status"] == "verification_failed"
    assert (
        api.get("/api/v1/incidents/INC-PRIMARY-001").json()["incident"]["status"] == "investigating"
    )


def test_response_rejects_unauthorized_and_stale_decisions(client):
    api, _ = client
    ingest_primary(api)
    action = api.post(
        "/api/v1/incidents/INC-PRIMARY-001/response-plans",
        json=action_payload(),
    ).json()
    action_id = action["action_id"]

    unauthorized = api.post(
        f"/api/v1/response-actions/{action_id}/approve",
        json={"actor_id": "intruder"},
    )
    assert unauthorized.status_code == 403
    assert unauthorized.json()["code"] == "actor_not_authorized"

    stale = api.post(
        f"/api/v1/response-actions/{action_id}/approve",
        json={"action_version": 99},
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "stale_action_version"

    rejected = api.post(
        f"/api/v1/response-actions/{action_id}/reject",
        json={"reason": "Analyst needs more evidence."},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"
