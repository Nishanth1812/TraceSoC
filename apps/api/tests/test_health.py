from fastapi.testclient import TestClient

from apps.api.app import main

client = TestClient(main.app)


def test_health_reports_healthy_database(monkeypatch):
    monkeypatch.setattr(main, "database_is_healthy", lambda: True)

    response = client.get("/api/v1/health", headers={"x-request-id": "req-123"})

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "req-123"
    assert response.json() == {
        "status": "ok",
        "service": "ok",
        "database": "ok",
        "schema_revision": "bootstrap",
        "request_id": "req-123",
    }


def test_health_does_not_claim_database_is_healthy_when_unavailable(monkeypatch):
    monkeypatch.setattr(main, "database_is_healthy", lambda: False)

    response = client.get("/api/v1/health")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["service"] == "ok"
    assert body["database"] == "unavailable"
    assert body["request_id"]
