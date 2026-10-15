"""Validate the frozen primary scenario without requiring application services."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "data" / "scenarios" / "primary-v1"


def load_events() -> list[dict]:
    with (SCENARIO / "events.jsonl").open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def main() -> None:
    events = load_events()
    expected = json.loads((SCENARIO / "expected.json").read_text(encoding="utf-8"))

    assert expected["scenario_id"] == "primary-v1"
    assert expected["tenant_id"] == "demo"
    assert len(events) == expected["event_count"]
    assert [event["source_event_id"] for event in events] == expected["expected_source_event_ids"]
    assert len({event["source_event_id"] for event in events}) == len(events)

    for event in events:
        assert event["event_time"].endswith("Z")
        assert event["source_type"] in {"authentication", "system", "endpoint", "network"}
        assert event["outcome"] in {"success", "failure", "blocked", "unknown"}

    primary_evidence = expected["candidate_incident"]["evidence"]
    assert primary_evidence == expected["expected_source_event_ids"]
    assert expected["response"] == {
        "action_type": "revoke_session",
        "target": "session-S104",
        "expected_postcondition": {"active": False},
    }

    print(
        f"Scenario {expected['scenario_id']} is valid: "
        f"{len(events)} events, incident {expected['candidate_incident']['id']}"
    )


if __name__ == "__main__":
    main()
