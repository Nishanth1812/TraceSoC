.PHONY: install lint test validate-scenario run

install:
	uv sync

lint:
	uv run ruff check .

test:
	uv run pytest

validate-scenario:
	uv run python scripts/validate_scenario.py

run:
	uv run uvicorn apps.api.app.main:app --reload --port 8000
