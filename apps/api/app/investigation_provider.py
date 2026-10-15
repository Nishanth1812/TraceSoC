"""Provider boundary and deterministic offline implementation."""

from collections.abc import Callable
from typing import Any, Protocol

from .investigation_tools import InvestigationToolRegistry


class ProviderFailure(Exception):
    """A provider could not produce a response."""


class InvestigatorProvider(Protocol):
    name: str

    def investigate(
        self,
        *,
        incident: dict[str, Any],
        tools: InvestigationToolRegistry,
    ) -> dict[str, Any]: ...


class MockInvestigator:
    name = "mock"

    def investigate(
        self,
        *,
        incident: dict[str, Any],
        tools: InvestigationToolRegistry,
    ) -> dict[str, Any]:
        """Use only structured tool results; log fields never become instructions."""

        incident_id = incident["incident"]["incident_id"]
        event_result = tools.call(
            "get_incident_events",
            {"incident_id": incident_id, "limit": 100},
        )
        events = event_result["items"]
        for event in events:
            tools.call(
                "get_event_details",
                {"incident_id": incident_id, "event_id": event["event_id"]},
            )

        entities = incident.get("entities", [])
        session_entity = next(
            (entity for entity in entities if entity["entity_type"] == "session"),
            None,
        )
        if session_entity is not None:
            tools.call(
                "get_related_events",
                {
                    "incident_id": incident_id,
                    "entity_id": session_entity["entity_id"],
                    "time_window_minutes": 1440,
                },
            )

        event_ids = [event["event_id"] for event in events]
        event_types = {event["event_type"] for event in events}
        session_id = next(
            (event.get("session_id") for event in events if event.get("session_id")), None
        )
        suspicious = "login_failure" in event_types and "login_success" in event_types
        observed_facts = [
            {
                "claim": f"The incident contains {len(events)} stored events in deterministic timeline order.",
                "evidence_event_ids": event_ids,
                "status": "observed",
            },
        ]
        if suspicious:
            observed_facts.append(
                {
                    "claim": "A successful login follows failed authentication activity.",
                    "evidence_event_ids": [
                        event["event_id"]
                        for event in events
                        if event["event_type"] in {"login_failure", "login_success"}
                    ],
                    "status": "observed",
                }
            )
        recommended_actions = []
        if session_id:
            recommended_actions.append(
                {
                    "action_type": "revoke_session",
                    "target": session_id,
                    "rationale": "Revoke the simulated session while preserving the evidence trail.",
                    "evidence_event_ids": [
                        event["event_id"]
                        for event in events
                        if event.get("session_id") == session_id
                    ],
                }
            )
        return {
            "schema_version": "1.0",
            "executive_summary": (
                "Stored evidence supports suspicious account activity; the deterministic findings "
                "remain the source of truth."
            ),
            "incident_assessment": incident["incident"]["title"],
            "competing_hypotheses": [
                {
                    "name": "Account compromise",
                    "assessment": "supported" if suspicious else "partially_supported",
                    "explanation": "The ordered evidence contains a failed-login burst and subsequent activity.",
                    "evidence_event_ids": event_ids,
                },
                {
                    "name": "Benign user error",
                    "assessment": "inconclusive",
                    "explanation": "The available telemetry does not establish user intent.",
                    "evidence_event_ids": [],
                },
            ],
            "observed_facts": observed_facts,
            "inferences": [
                {
                    "claim": "The activity warrants containment review, not an assertion of confirmed compromise.",
                    "evidence_event_ids": event_ids,
                    "status": "inferred",
                }
            ],
            "contradicting_evidence": [],
            "missing_evidence": [
                "No independent identity confirmation or endpoint memory evidence is available in this fixture."
            ],
            "affected_entities": [
                {
                    "entity_id": entity["entity_id"],
                    "entity_type": entity["entity_type"],
                    "display_value": entity["display_value"],
                    "evidence_event_ids": event_ids,
                }
                for entity in entities
            ],
            "severity_explanation": f"Deterministic incident severity is {incident['incident']['severity']}.",
            "confidence_explanation": (
                f"Deterministic incident confidence is {incident['incident']['confidence']}; "
                "this is a category, not a calibrated probability."
            ),
            "recommended_actions": recommended_actions,
            "referenced_event_ids": event_ids,
            "limitations": [
                "The provider is an offline deterministic mock and cannot establish intent.",
                "Only read-only allowlisted tools were available.",
            ],
        }


class FailingInvestigator:
    name = "failing"

    def investigate(
        self,
        *,
        incident: dict[str, Any],
        tools: InvestigationToolRegistry,
    ) -> dict[str, Any]:
        del incident, tools
        raise ProviderFailure("configured provider failure")


ProviderFactory = Callable[[str], InvestigatorProvider]


def default_provider_factory(name: str) -> InvestigatorProvider:
    if name == "mock":
        return MockInvestigator()
    if name == "failing":
        return FailingInvestigator()
    raise ProviderFailure(f"provider {name!r} is unavailable")
