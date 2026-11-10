"""Small, transparent deterministic rule set for the primary scenario."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

RULE_VERSION = "1.0"
AUTH_BURST = "AUTH-BURST-001"
AUTH_SUCCESS_AFTER_BURST = "AUTH-SUCCESS-AFTER-BURST-001"
PRIVILEGED_FOLLOW_ON = "PRIVILEGED-FOLLOW-ON-001"


@dataclass(frozen=True)
class Detection:
    rule_id: str
    rule_version: str
    event_ids: tuple[str, ...]
    correlation_key: str
    observed_start: datetime
    observed_end: datetime
    title: str
    description: str
    severity: str
    severity_factors: tuple[str, ...]
    finding_status: str = "inferred"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _ordered(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        events,
        key=lambda event: (
            _utc(event["event_time"]),
            _utc(event["ingested_at"]),
            event["event_id"],
        ),
    )


def _time_range(events: list[dict[str, Any]]) -> tuple[datetime, datetime]:
    ordered = _ordered(events)
    return _utc(ordered[0]["event_time"]), _utc(ordered[-1]["event_time"])


def _correlation_key(events: list[dict[str, Any]]) -> str:
    ordered = _ordered(events)
    username = next((event.get("username") for event in ordered if event.get("username")), None)
    source_ip = next((event.get("source_ip") for event in ordered if event.get("source_ip")), None)
    host_id = next((event.get("host_id") for event in ordered if event.get("host_id")), None)
    identity = f"user={username or 'unknown'}|source={source_ip or 'unknown'}"
    if username is None and host_id is not None:
        identity = f"host={host_id}"
    bucket = _utc(ordered[0]["event_time"]).strftime("%Y%m%d%H")
    return f"{identity}|bucket={bucket}"


def _detection(
    rule_id: str,
    events: list[dict[str, Any]],
    *,
    title: str,
    description: str,
    severity: str,
    factors: tuple[str, ...],
) -> Detection:
    ordered = _ordered(events)
    start, end = _time_range(ordered)
    return Detection(
        rule_id=rule_id,
        rule_version=RULE_VERSION,
        event_ids=tuple(event["event_id"] for event in ordered),
        correlation_key=_correlation_key(ordered),
        observed_start=start,
        observed_end=end,
        title=title,
        description=description,
        severity=severity,
        severity_factors=factors,
    )


def detect(events: list[dict[str, Any]]) -> list[Detection]:
    """Evaluate all persisted events, independent of ingestion order."""

    ordered = _ordered(events)
    detections: list[Detection] = []

    failed_by_identity: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for event in ordered:
        if (
            event.get("source_type") == "authentication"
            and event.get("event_type") == "login_failure"
            and event.get("username")
            and event.get("source_ip")
        ):
            failed_by_identity.setdefault((event["username"], event["source_ip"]), []).append(event)

    for (username, source_ip), failures in failed_by_identity.items():
        for index, first in enumerate(failures):
            window_end = _utc(first["event_time"]) + timedelta(minutes=5)
            window = [
                event for event in failures[index:] if _utc(event["event_time"]) <= window_end
            ]
            if len(window) >= 3:
                detections.append(
                    _detection(
                        AUTH_BURST,
                        window,
                        title="Repeated failed authentication",
                        description=(
                            f"At least three failed logins for {username} from {source_ip} "
                            "occurred within five minutes. This is a signal, not proof "
                            "of compromise."
                        ),
                        severity="medium",
                        factors=("three_or_more_failures", "five_minute_window"),
                    )
                )
                break

    for event in ordered:
        if not (
            event.get("source_type") == "authentication"
            and event.get("event_type") == "login_success"
            and event.get("username")
            and event.get("source_ip")
        ):
            continue
        success_time = _utc(event["event_time"])
        failures = [
            candidate
            for candidate in failed_by_identity.get((event["username"], event["source_ip"]), [])
            if success_time - timedelta(minutes=10) <= _utc(candidate["event_time"]) < success_time
        ]
        if len(failures) >= 3:
            detections.append(
                _detection(
                    AUTH_SUCCESS_AFTER_BURST,
                    [*failures, event],
                    title="Successful login followed an authentication burst",
                    description=(
                        "A successful login followed repeated failures for the same account and "
                        "source IP. The sequence is suspicious but remains an inferred finding."
                    ),
                    severity="high",
                    factors=("same_account", "same_source_ip", "ten_minute_follow_on"),
                )
            )

    for success in ordered:
        if not (
            success.get("source_type") == "authentication"
            and success.get("event_type") == "login_success"
            and success.get("username")
            and success.get("host_id")
        ):
            continue
        end_time = _utc(success["event_time"]) + timedelta(minutes=15)
        follow_on = [
            event
            for event in ordered
            if success["event_id"] != event["event_id"]
            and event.get("username") == success.get("username")
            and event.get("host_id") == success.get("host_id")
            and _utc(success["event_time"]) < _utc(event["event_time"]) <= end_time
            and event.get("event_type")
            in {
                "privileged_session_started",
                "sensitive_process_started",
                "unusual_outbound_connection",
            }
        ]
        if any(
            event["event_type"] in {"privileged_session_started", "sensitive_process_started"}
            for event in follow_on
        ):
            detections.append(
                _detection(
                    PRIVILEGED_FOLLOW_ON,
                    [success, *follow_on],
                    title="Privileged or sensitive follow-on activity",
                    description=(
                        "A successful login was followed by privileged session or sensitive "
                        "process "
                        "activity on the related host; outbound activity is included when observed."
                    ),
                    severity="high",
                    factors=("same_account", "same_host", "fifteen_minute_follow_on"),
                )
            )

    # The rules are evaluated independently, but an analyst should see one
    # candidate incident when their bounded entity/time windows overlap.
    return detections


def group_detections(
    detections: list[Detection],
    event_by_id: dict[str, dict[str, Any]],
) -> list[list[Detection]]:
    """Union detections that share a canonical entity in a 30-minute window."""

    if not detections:
        return []
    parents = list(range(len(detections)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    def entities(detection: Detection) -> set[tuple[str, str]]:
        values: set[tuple[str, str]] = set()
        for event_id in detection.event_ids:
            event = event_by_id[event_id]
            for field in ("username", "host_id", "source_ip", "session_id"):
                if event.get(field):
                    values.add((field, event[field]))
        return values

    detection_entities = [entities(detection) for detection in detections]
    for left, left_detection in enumerate(detections):
        for right in range(left + 1, len(detections)):
            right_detection = detections[right]
            starts = min(left_detection.observed_start, right_detection.observed_start)
            ends = max(left_detection.observed_end, right_detection.observed_end)
            if (
                ends - starts <= timedelta(minutes=30)
                and detection_entities[left] & detection_entities[right]
            ):
                union(left, right)

    grouped: dict[int, list[Detection]] = {}
    for index, detection in enumerate(detections):
        grouped.setdefault(find(index), []).append(detection)
    return list(grouped.values())
