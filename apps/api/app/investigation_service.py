"""Durable orchestration for constrained investigations."""

import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import sqlalchemy as sa

from .investigation_provider import ProviderFactory, ProviderFailure, default_provider_factory
from .investigation_tools import InvestigationToolRegistry, ToolFailure
from .repository import TENANT_ID
from .schema import audit_logs, incidents, investigation_runs, investigation_steps
from .schemas.investigation import InvestigationResult


class InvestigationError(Exception):
    def __init__(
        self, status_code: int, code: str, message: str, details: dict[str, Any] | None = None
    ):
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(message)


def _now() -> datetime:
    return datetime.now(UTC)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _timestamp(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


class InvestigationService:
    def __init__(
        self,
        engine,
        *,
        tenant_id: str = TENANT_ID,
        provider_factory: ProviderFactory = default_provider_factory,
    ) -> None:
        self.engine = engine
        self.tenant_id = tenant_id
        self.provider_factory = provider_factory

    def start(self, incident_id: str, provider_name: str = "mock") -> dict[str, Any]:
        run_id = str(uuid4())
        created_at = _now()
        with self.engine.begin() as connection:
            incident = (
                connection.execute(
                    sa.select(incidents).where(
                        incidents.c.incident_id == incident_id,
                        incidents.c.tenant_id == self.tenant_id,
                    )
                )
                .mappings()
                .first()
            )
            if incident is None:
                raise InvestigationError(404, "incident_not_found", "incident was not found")
            connection.execute(
                sa.insert(investigation_runs).values(
                    run_id=run_id,
                    tenant_id=self.tenant_id,
                    incident_id=incident_id,
                    provider=provider_name,
                    status="running",
                    tool_call_count=0,
                    created_at=created_at,
                )
            )
            self._audit(
                connection,
                incident_id=incident_id,
                actor_id="analyst-demo",
                event_type="investigation_started",
                reason="constrained investigation requested",
                metadata={"provider": provider_name, "run_id": run_id},
            )

        step_number = 0

        def step_hook(
            tool_name: str,
            arguments: dict[str, Any],
            result: dict[str, Any],
            step_status: str,
        ) -> None:
            nonlocal step_number
            step_number += 1
            with self.engine.begin() as connection:
                connection.execute(
                    sa.insert(investigation_steps).values(
                        step_id=str(uuid4()),
                        run_id=run_id,
                        step_number=step_number,
                        tool_name=tool_name,
                        status=step_status,
                        arguments_json=_json(self._redact_arguments(arguments)),
                        result_json=_json(result),
                        created_at=_now(),
                    )
                )
                connection.execute(
                    sa.update(investigation_runs)
                    .where(investigation_runs.c.run_id == run_id)
                    .values(tool_call_count=step_number)
                )

        try:
            incident_detail = self._incident_detail(incident_id)
            provider = self.provider_factory(provider_name)
            tools = InvestigationToolRegistry(
                self.engine,
                tenant_id=self.tenant_id,
                incident_id=incident_id,
                step_hook=step_hook,
            )
            raw_result = provider.investigate(incident=incident_detail, tools=tools)
            result = InvestigationResult.model_validate(raw_result)
            self._validate_citations(result, incident_detail)
        except (ProviderFailure, ToolFailure) as error:
            code = getattr(error, "code", "provider_failure")
            message = getattr(error, "message", str(error))
            details = getattr(error, "details", {})
            return self._finish_failure(run_id, provider_name, code, message, details)
        except Exception as error:  # invalid provider output is isolated from evidence data
            return self._finish_failure(
                run_id,
                provider_name,
                "invalid_provider_output",
                "provider output failed the investigation contract",
                {"error_type": type(error).__name__},
            )

        completed_at = _now()
        with self.engine.begin() as connection:
            connection.execute(
                sa.update(investigation_runs)
                .where(investigation_runs.c.run_id == run_id)
                .values(
                    status="completed",
                    tool_call_count=step_number,
                    result_json=_json(result.model_dump(mode="json")),
                    completed_at=completed_at,
                )
            )
            self._audit(
                connection,
                incident_id=incident_id,
                actor_id="analyst-demo",
                event_type="investigation_completed",
                reason="validated evidence-cited result stored",
                metadata={"run_id": run_id, "tool_call_count": step_number},
            )
        return self.get(run_id)  # type: ignore[return-value]

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            run = (
                connection.execute(
                    sa.select(investigation_runs).where(
                        investigation_runs.c.run_id == run_id,
                        investigation_runs.c.tenant_id == self.tenant_id,
                    )
                )
                .mappings()
                .first()
            )
            if run is None:
                return None
            return self._run_response(dict(run))

    def _finish_failure(
        self,
        run_id: str,
        provider_name: str,
        code: str,
        message: str,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        completed_at = _now()
        with self.engine.begin() as connection:
            run = (
                connection.execute(
                    sa.select(investigation_runs).where(investigation_runs.c.run_id == run_id)
                )
                .mappings()
                .one()
            )
            error_json = _json({"code": code, "message": message, "details": details})
            connection.execute(
                sa.update(investigation_runs)
                .where(investigation_runs.c.run_id == run_id)
                .values(status="failed", error_json=error_json, completed_at=completed_at)
            )
            self._audit(
                connection,
                incident_id=run["incident_id"],
                actor_id="analyst-demo",
                event_type="investigation_failed",
                reason=message,
                metadata={"run_id": run_id, "provider": provider_name, "code": code},
            )
        return self.get(run_id)  # type: ignore[return-value]

    def _incident_detail(self, incident_id: str) -> dict[str, Any]:
        # Reuse the evidence repository's bounded, evidence-linked response.
        from .repository import EvidenceRepository

        detail = EvidenceRepository(self.engine, tenant_id=self.tenant_id).get_incident(incident_id)
        if detail is None:
            raise InvestigationError(404, "incident_not_found", "incident was not found")
        return detail

    def _validate_citations(self, result: InvestigationResult, incident: dict[str, Any]) -> None:
        allowed = set(incident["incident"].get("evidence_event_ids", []))
        cited: set[str] = set(result.referenced_event_ids)
        for group in (
            result.observed_facts,
            result.inferences,
            result.contradicting_evidence,
            result.competing_hypotheses,
            result.affected_entities,
            result.recommended_actions,
        ):
            for item in group:
                cited.update(item.evidence_event_ids)
        unknown = cited - allowed
        if unknown:
            raise InvestigationError(
                500,
                "invalid_evidence_citation",
                "provider cited an event outside the incident evidence boundary",
                {"event_ids": sorted(unknown)},
            )

    def _run_response(self, run: dict[str, Any]) -> dict[str, Any]:
        return {
            "run_id": run["run_id"],
            "incident_id": run["incident_id"],
            "tenant_id": run["tenant_id"],
            "provider": run["provider"],
            "status": run["status"],
            "tool_call_count": run["tool_call_count"],
            "result": json.loads(run["result_json"]) if run.get("result_json") else None,
            "error": json.loads(run["error_json"]) if run.get("error_json") else None,
            "created_at": _timestamp(run["created_at"]),
            "completed_at": _timestamp(run.get("completed_at")),
        }

    @staticmethod
    def _redact_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in arguments.items()
            if key not in {"raw_event", "raw_payload", "content", "prompt"}
        }

    @staticmethod
    def _audit(
        connection,
        *,
        incident_id: str,
        actor_id: str,
        event_type: str,
        reason: str,
        metadata: dict[str, Any],
    ) -> None:
        connection.execute(
            sa.insert(audit_logs).values(
                audit_id=str(uuid4()),
                tenant_id=TENANT_ID,
                incident_id=incident_id,
                action_id=None,
                actor_id=actor_id,
                event_type=event_type,
                previous_state=None,
                new_state=None,
                reason=reason[:1000],
                metadata_json=_json(metadata),
                created_at=_now(),
            )
        )
