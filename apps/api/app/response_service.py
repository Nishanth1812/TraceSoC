"""Backend-enforced, simulation-only response workflow."""

import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import sqlalchemy as sa

from .repository import TENANT_ID
from .schema import (
    audit_logs,
    incident_events,
    incidents,
    response_actions,
    response_executions,
    security_events,
    simulated_state,
)
from .schemas.response import ActionDecisionRequest, ResponsePlanRequest


class ResponseError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
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
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class ResponseService:
    """Own all response state changes and keep them inside the simulator."""

    allowed_actor = "analyst-demo"
    action_type = "revoke_session"

    def __init__(self, engine, *, tenant_id: str = TENANT_ID) -> None:
        self.engine = engine
        self.tenant_id = tenant_id

    def propose(self, incident_id: str, request: ResponsePlanRequest) -> dict[str, Any]:
        actor = self._require_actor(request.actor_id)
        session_id = request.session_id()
        now = _now()
        with self.engine.begin() as connection:
            incident = self._incident(connection, incident_id)
            evidence_event_ids = self._validate_evidence(
                connection, incident_id, request.evidence_event_ids
            )
            session = self._session_event(connection, incident_id, session_id)
            if session is None:
                raise ResponseError(
                    422,
                    "target_not_in_incident",
                    "the response target must be a session observed in the incident",
                    {"target": session_id},
                )
            if request.expected_postcondition.get("active") is not False:
                raise ResponseError(
                    422,
                    "invalid_postcondition",
                    "revoke_session requires the postcondition active=false",
                )

            version = request.action_version or self._next_version(connection, incident_id)
            duplicate = connection.execute(
                sa.select(response_actions.c.action_id).where(
                    response_actions.c.tenant_id == self.tenant_id,
                    response_actions.c.incident_id == incident_id,
                    response_actions.c.action_type == self.action_type,
                    response_actions.c.action_version == version,
                )
            ).scalar_one_or_none()
            if duplicate is not None:
                raise ResponseError(
                    409,
                    "action_version_exists",
                    "the requested response action version already exists",
                    {"action_id": duplicate, "action_version": version},
                )

            action_id = str(uuid4())
            connection.execute(
                sa.insert(response_actions).values(
                    action_id=action_id,
                    tenant_id=self.tenant_id,
                    incident_id=incident_id,
                    action_type=self.action_type,
                    action_version=version,
                    target=session_id,
                    status="awaiting_approval",
                    evidence_event_ids=_json(evidence_event_ids),
                    rationale=request.rationale,
                    risk=request.risk,
                    expected_outcome=request.expected_outcome,
                    operational_impact=request.operational_impact,
                    preconditions=_json(request.preconditions),
                    rollback_plan=request.rollback_plan,
                    verification_method=request.verification_method,
                    expected_postcondition=_json(request.expected_postcondition),
                    created_at=now,
                    updated_at=now,
                )
            )
            self._ensure_simulated_session(connection, session_id, session, now)
            self._set_incident_status(connection, incident, "awaiting_approval", now)
            self._audit(
                connection,
                incident_id=incident_id,
                action_id=action_id,
                actor_id=actor,
                event_type="response_proposed",
                previous_state=incident["status"],
                new_state="awaiting_approval",
                reason=request.rationale,
                metadata={"action_type": self.action_type, "action_version": version},
                created_at=now,
            )
            return self._get_action(connection, action_id)

    def approve(self, action_id: str, request: ActionDecisionRequest) -> dict[str, Any]:
        return self._decide(action_id, request, approved=True)

    def reject(self, action_id: str, request: ActionDecisionRequest) -> dict[str, Any]:
        return self._decide(action_id, request, approved=False)

    def execute(
        self,
        action_id: str,
        request: ActionDecisionRequest,
        idempotency_key: str,
    ) -> dict[str, Any]:
        actor = self._require_actor(request.actor_id)
        if not idempotency_key.strip() or len(idempotency_key) > 255:
            raise ResponseError(
                400, "invalid_idempotency_key", "a valid Idempotency-Key is required"
            )
        now = _now()
        with self.engine.begin() as connection:
            action = self._action(connection, action_id)
            self._require_version(action, request.action_version)
            existing_execution = (
                connection.execute(
                    sa.select(response_executions).where(
                        response_executions.c.tenant_id == self.tenant_id,
                        response_executions.c.idempotency_key == idempotency_key,
                    )
                )
                .mappings()
                .first()
            )
            if existing_execution is not None:
                if existing_execution["action_id"] != action_id:
                    raise ResponseError(
                        409,
                        "idempotency_key_reused",
                        "the idempotency key belongs to another response action",
                    )
                return self._get_action(connection, action_id)
            if action["status"] in {"succeeded", "verified", "verification_failed", "inconclusive"}:
                return self._get_action(connection, action_id)
            if action["status"] != "approved":
                raise ResponseError(
                    409,
                    "action_not_approved",
                    "only an approved response action can execute",
                    {"status": action["status"]},
                )

            before = self._simulated_session(connection, action["target"])
            if before is None:
                raise ResponseError(
                    409, "target_state_missing", "simulated target state is unavailable"
                )
            after = dict(before)
            after["active"] = False
            connection.execute(
                sa.update(simulated_state)
                .where(
                    simulated_state.c.tenant_id == self.tenant_id,
                    simulated_state.c.session_id == action["target"],
                )
                .values(active=False, state_json=_json(after), updated_at=now)
            )
            execution_id = str(uuid4())
            execution_result = {
                "simulated": True,
                "action": self.action_type,
                "postcondition_written": True,
            }
            connection.execute(
                sa.insert(response_executions).values(
                    execution_id=execution_id,
                    tenant_id=self.tenant_id,
                    action_id=action_id,
                    idempotency_key=idempotency_key,
                    response_json=_json(execution_result),
                    created_at=now,
                )
            )
            connection.execute(
                sa.update(response_actions)
                .where(response_actions.c.action_id == action_id)
                .values(
                    status="succeeded",
                    execution_actor_id=actor,
                    execution_idempotency_key=idempotency_key,
                    executed_at=now,
                    before_state=_json(before),
                    after_state=_json(after),
                    execution_result=_json(execution_result),
                    updated_at=now,
                )
            )
            self._audit(
                connection,
                incident_id=action["incident_id"],
                action_id=action_id,
                actor_id=actor,
                event_type="response_executed",
                previous_state="approved",
                new_state="succeeded",
                reason=request.reason or "approved simulated action executed",
                metadata={"execution_id": execution_id, "simulated": True},
                created_at=now,
            )
            return self._get_action(connection, action_id)

    def verify(self, action_id: str) -> dict[str, Any]:
        now = _now()
        with self.engine.begin() as connection:
            action = self._action(connection, action_id)
            if action["status"] not in {
                "succeeded",
                "verified",
                "verification_failed",
                "inconclusive",
            }:
                raise ResponseError(
                    409,
                    "action_not_executed",
                    "a response action must execute before verification",
                    {"status": action["status"]},
                )
            observed = self._simulated_session(connection, action["target"])
            expected = json.loads(action["expected_postcondition"])
            if observed is None:
                verification_status = "inconclusive"
                observed_state = None
            else:
                observed_state = {
                    "active": bool(observed["active"]),
                    "session_id": action["target"],
                }
                verification_status = (
                    "verified"
                    if all(observed_state.get(key) == value for key, value in expected.items())
                    else "verification_failed"
                )
            connection.execute(
                sa.update(response_actions)
                .where(response_actions.c.action_id == action_id)
                .values(
                    status=verification_status,
                    verification_status=verification_status,
                    verification_observed_state=_json(observed_state) if observed_state else None,
                    verified_at=now,
                    updated_at=now,
                )
            )
            incident = self._incident(connection, action["incident_id"])
            next_incident_status = (
                "contained" if verification_status == "verified" else "investigating"
            )
            self._set_incident_status(connection, incident, next_incident_status, now)
            self._audit(
                connection,
                incident_id=action["incident_id"],
                action_id=action_id,
                actor_id="system-verifier",
                event_type="response_verified",
                previous_state=action["status"],
                new_state=verification_status,
                reason="independent simulated-state verification completed",
                metadata={"observed_state": observed_state, "expected_postcondition": expected},
                created_at=now,
            )
            return self._verification_response(
                action, verification_status, expected, observed_state, now
            )

    def get_action(self, action_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            try:
                return self._get_action(connection, action_id, required=False)
            except ResponseError:
                return None

    def get_audit(self, incident_id: str) -> list[dict[str, Any]] | None:
        with self.engine.connect() as connection:
            incident = self._incident(connection, incident_id, required=False)
            if incident is None:
                return None
            rows = connection.execute(
                sa.select(audit_logs)
                .where(
                    audit_logs.c.tenant_id == self.tenant_id,
                    audit_logs.c.incident_id == incident_id,
                )
                .order_by(audit_logs.c.created_at, audit_logs.c.audit_id)
            ).mappings()
            return [self._audit_response(dict(row)) for row in rows]

    def _decide(
        self,
        action_id: str,
        request: ActionDecisionRequest,
        *,
        approved: bool,
    ) -> dict[str, Any]:
        actor = self._require_actor(request.actor_id)
        now = _now()
        with self.engine.begin() as connection:
            action = self._action(connection, action_id)
            self._require_version(action, request.action_version)
            if action["status"] not in {"proposed", "awaiting_approval"}:
                raise ResponseError(
                    409,
                    "action_not_pending",
                    "only a pending response action can be approved or rejected",
                    {"status": action["status"]},
                )
            next_state = "approved" if approved else "rejected"
            values: dict[str, Any] = {"status": next_state, "updated_at": now}
            if approved:
                values.update(approval_actor_id=actor, approved_at=now)
            else:
                values.update(
                    rejection_actor_id=actor,
                    rejected_at=now,
                    rejection_reason=request.reason or "action rejected by analyst",
                )
            connection.execute(
                sa.update(response_actions)
                .where(response_actions.c.action_id == action_id)
                .values(**values)
            )
            incident = self._incident(connection, action["incident_id"])
            incident_state = "responding" if approved else "investigating"
            self._set_incident_status(connection, incident, incident_state, now)
            self._audit(
                connection,
                incident_id=action["incident_id"],
                action_id=action_id,
                actor_id=actor,
                event_type="response_approved" if approved else "response_rejected",
                previous_state=action["status"],
                new_state=next_state,
                reason=request.reason or ("response approved" if approved else "response rejected"),
                metadata={},
                created_at=now,
            )
            return self._get_action(connection, action_id)

    def _incident(
        self,
        connection,
        incident_id: str,
        *,
        required: bool = True,
    ) -> dict[str, Any] | None:
        row = (
            connection.execute(
                sa.select(incidents).where(
                    incidents.c.incident_id == incident_id,
                    incidents.c.tenant_id == self.tenant_id,
                )
            )
            .mappings()
            .first()
        )
        if row is None and required:
            raise ResponseError(404, "incident_not_found", "incident was not found")
        return dict(row) if row is not None else None

    def _action(self, connection, action_id: str) -> dict[str, Any]:
        row = (
            connection.execute(
                sa.select(response_actions).where(
                    response_actions.c.action_id == action_id,
                    response_actions.c.tenant_id == self.tenant_id,
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            raise ResponseError(404, "response_action_not_found", "response action was not found")
        return dict(row)

    def _get_action(
        self,
        connection,
        action_id: str,
        *,
        required: bool = True,
    ) -> dict[str, Any] | None:
        try:
            action = self._action(connection, action_id)
        except ResponseError:
            if required:
                raise
            return None
        execution = (
            connection.execute(
                sa.select(response_executions)
                .where(response_executions.c.action_id == action_id)
                .order_by(response_executions.c.created_at.desc())
            )
            .mappings()
            .first()
        )
        return self._action_response(action, dict(execution) if execution else None)

    def _validate_evidence(self, connection, incident_id: str, requested: list[str]) -> list[str]:
        rows = list(
            connection.execute(
                sa.select(
                    security_events.c.event_id,
                    security_events.c.source_event_id,
                )
                .join(incident_events, incident_events.c.event_id == security_events.c.event_id)
                .where(
                    incident_events.c.incident_id == incident_id,
                    security_events.c.tenant_id == self.tenant_id,
                )
            ).mappings()
        )
        by_id = {row["event_id"]: row["event_id"] for row in rows}
        by_source = {
            row["source_event_id"]: row["event_id"] for row in rows if row["source_event_id"]
        }
        resolved = [by_id.get(item) or by_source.get(item) for item in requested]
        if any(item is None for item in resolved):
            raise ResponseError(
                422,
                "evidence_outside_incident",
                "all evidence references must belong to the incident",
                {"evidence_event_ids": requested},
            )
        return list(dict.fromkeys(resolved))

    def _session_event(
        self, connection, incident_id: str, session_id: str
    ) -> dict[str, Any] | None:
        row = (
            connection.execute(
                sa.select(security_events)
                .join(incident_events, incident_events.c.event_id == security_events.c.event_id)
                .where(
                    incident_events.c.incident_id == incident_id,
                    security_events.c.tenant_id == self.tenant_id,
                    security_events.c.session_id == session_id,
                )
                .order_by(security_events.c.event_time)
            )
            .mappings()
            .first()
        )
        return dict(row) if row else None

    def _ensure_simulated_session(
        self, connection, session_id: str, event: dict[str, Any], now: datetime
    ) -> None:
        existing = (
            connection.execute(
                sa.select(simulated_state).where(
                    simulated_state.c.tenant_id == self.tenant_id,
                    simulated_state.c.session_id == session_id,
                )
            )
            .mappings()
            .first()
        )
        if existing is None:
            connection.execute(
                sa.insert(simulated_state).values(
                    tenant_id=self.tenant_id,
                    session_id=session_id,
                    active=True,
                    username=event.get("username"),
                    host_id=event.get("host_id"),
                    state_json=_json({"active": True, "session_id": session_id}),
                    updated_at=now,
                )
            )

    def _simulated_session(self, connection, session_id: str) -> dict[str, Any] | None:
        row = (
            connection.execute(
                sa.select(simulated_state).where(
                    simulated_state.c.tenant_id == self.tenant_id,
                    simulated_state.c.session_id == session_id,
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            return None
        value = json.loads(row["state_json"] or "{}")
        value.setdefault("active", bool(row["active"]))
        value.setdefault("session_id", session_id)
        return value

    def _set_incident_status(
        self, connection, incident: dict[str, Any], new_status: str, now: datetime
    ) -> None:
        current = incident["status"]
        allowed = {
            "investigating": {
                "awaiting_approval",
                "responding",
                "contained",
                "false_positive",
                "resolved",
            },
            "awaiting_approval": {"investigating", "responding"},
            "responding": {"investigating", "contained"},
            "contained": {"investigating", "resolved"},
            "new": {"investigating", "false_positive"},
        }
        if current != new_status and new_status not in allowed.get(current, set()):
            raise ResponseError(
                409,
                "invalid_incident_transition",
                "the incident cannot enter the requested response state",
                {"from": current, "to": new_status},
            )
        if current != new_status:
            connection.execute(
                sa.update(incidents)
                .where(incidents.c.incident_id == incident["incident_id"])
                .values(status=new_status, updated_at=now)
            )

    def _next_version(self, connection, incident_id: str) -> int:
        value = connection.execute(
            sa.select(sa.func.max(response_actions.c.action_version)).where(
                response_actions.c.tenant_id == self.tenant_id,
                response_actions.c.incident_id == incident_id,
                response_actions.c.action_type == self.action_type,
            )
        ).scalar_one()
        return int(value or 0) + 1

    def _require_actor(self, actor_id: str) -> str:
        if actor_id != self.allowed_actor:
            raise ResponseError(
                403,
                "actor_not_authorized",
                "the local MVP only permits the analyst-demo actor",
                {"actor_id": actor_id},
            )
        return actor_id

    @staticmethod
    def _require_version(action: dict[str, Any], requested: int | None) -> None:
        if requested is not None and requested != action["action_version"]:
            raise ResponseError(
                409,
                "stale_action_version",
                "the requested action version is stale",
                {"expected": action["action_version"], "received": requested},
            )

    def _audit(
        self,
        connection,
        *,
        incident_id: str,
        action_id: str | None,
        actor_id: str,
        event_type: str,
        previous_state: str | None,
        new_state: str | None,
        reason: str,
        metadata: dict[str, Any],
        created_at: datetime,
    ) -> None:
        connection.execute(
            sa.insert(audit_logs).values(
                audit_id=str(uuid4()),
                tenant_id=self.tenant_id,
                incident_id=incident_id,
                action_id=action_id,
                actor_id=actor_id,
                event_type=event_type,
                previous_state=previous_state,
                new_state=new_state,
                reason=reason[:1000],
                metadata_json=_json(metadata),
                created_at=created_at,
            )
        )

    def _action_response(
        self, action: dict[str, Any], execution: dict[str, Any] | None
    ) -> dict[str, Any]:
        return {
            "action_id": action["action_id"],
            "incident_id": action["incident_id"],
            "tenant_id": action["tenant_id"],
            "action_type": action["action_type"],
            "action_version": action["action_version"],
            "target": action["target"],
            "status": action["status"],
            "evidence_event_ids": json.loads(action["evidence_event_ids"]),
            "rationale": action["rationale"],
            "risk": action["risk"],
            "expected_outcome": action["expected_outcome"],
            "operational_impact": action["operational_impact"],
            "preconditions": json.loads(action["preconditions"]),
            "rollback_plan": action["rollback_plan"],
            "verification_method": action["verification_method"],
            "expected_postcondition": json.loads(action["expected_postcondition"]),
            "approval": {
                "actor_id": action["approval_actor_id"],
                "approved_at": _timestamp(action["approved_at"]),
            }
            if action["approval_actor_id"]
            else None,
            "execution": {
                "execution_id": execution["execution_id"] if execution else None,
                "idempotency_key": action["execution_idempotency_key"],
                "executed_at": _timestamp(action["executed_at"]),
                "before_state": json.loads(action["before_state"])
                if action["before_state"]
                else None,
                "after_state": json.loads(action["after_state"]) if action["after_state"] else None,
                "result": json.loads(action["execution_result"])
                if action["execution_result"]
                else None,
            }
            if action["executed_at"]
            else None,
            "verification": {
                "status": action["verification_status"],
                "observed_state": json.loads(action["verification_observed_state"])
                if action["verification_observed_state"]
                else None,
                "checked_at": _timestamp(action["verified_at"]),
            }
            if action["verification_status"]
            else None,
            "created_at": _timestamp(action["created_at"]),
            "updated_at": _timestamp(action["updated_at"]),
        }

    def _verification_response(
        self,
        action: dict[str, Any],
        status: str,
        expected: dict[str, Any],
        observed: dict[str, Any] | None,
        checked_at: datetime,
    ) -> dict[str, Any]:
        return {
            "action_id": action["action_id"],
            "incident_id": action["incident_id"],
            "status": status,
            "expected_postcondition": expected,
            "observed_state": observed,
            "evidence": [f"simulated_state:{action['target']}"],
            "checked_at": _timestamp(checked_at),
        }

    @staticmethod
    def _audit_response(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "audit_id": row["audit_id"],
            "tenant_id": row["tenant_id"],
            "incident_id": row["incident_id"],
            "action_id": row["action_id"],
            "actor_id": row["actor_id"],
            "event_type": row["event_type"],
            "previous_state": row["previous_state"],
            "new_state": row["new_state"],
            "reason": row["reason"],
            "metadata": json.loads(row["metadata_json"] or "{}"),
            "created_at": _timestamp(row["created_at"]),
        }
