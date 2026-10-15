import json
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .config import get_settings
from .database import database_is_healthy, engine, initialize_schema
from .ingestion import ParseFailure
from .investigation_service import InvestigationError, InvestigationService
from .repository import MAX_PAGE_SIZE, EvidenceRepository
from .response_service import ResponseError, ResponseService
from .schemas.health import HealthResponse
from .schemas.investigation import InvestigationRequest
from .schemas.response import ActionDecisionRequest, ResponsePlanRequest

settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0")
repository = EvidenceRepository(engine)
investigations = InvestigationService(engine)
responses = ResponseService(engine)

# SQLite is the documented no-service development/test configuration.  The
# PostgreSQL path remains migration-managed and is never silently replaced.
if engine.dialect.name == "sqlite":
    initialize_schema(engine)


class APIError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ):
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}


def _raise_service_error(error: InvestigationError | ResponseError) -> None:
    raise APIError(error.status_code, error.code, error.message, error.details) from error


@app.exception_handler(APIError)
async def api_error_handler(request: Request, error: APIError) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content={
            "code": error.code,
            "message": error.message,
            "details": error.details,
            "request_id": getattr(request.state, "request_id", str(uuid4())),
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, error: RequestValidationError) -> JSONResponse:
    del error
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "code": "invalid_request",
            "message": "request validation failed",
            "details": {},
            "request_id": getattr(request.state, "request_id", str(uuid4())),
        },
    )


@app.middleware("http")
async def request_id_middleware(request: Request, call_next) -> Response:
    request_id = request.headers.get("x-request-id") or str(uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["x-request-id"] = request_id
    return response


def _require_idempotency_key(request: Request) -> str:
    key = request.headers.get("idempotency-key", "").strip()
    if not key:
        raise APIError(
            status.HTTP_400_BAD_REQUEST,
            "missing_idempotency_key",
            "Idempotency-Key is required for ingestion runs",
        )
    if len(key) > 255:
        raise APIError(
            status.HTTP_400_BAD_REQUEST,
            "invalid_idempotency_key",
            "Idempotency-Key must be at most 255 characters",
        )
    return key


async def _json_body(request: Request) -> Any:
    body = await request.body()
    if len(body) > settings.max_payload_bytes:
        raise APIError(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            "payload_too_large",
            "request payload exceeds the configured limit",
            {"max_bytes": settings.max_payload_bytes},
        )
    try:
        return json.loads(body)
    except json.JSONDecodeError as error:
        raise APIError(
            status.HTTP_400_BAD_REQUEST,
            "invalid_json",
            "request body is not valid JSON",
            {"line": error.lineno, "column": error.colno},
        ) from error


def _batch_records(payload: Any) -> tuple[list[Any], str]:
    if isinstance(payload, list):
        records, source = payload, "json-batch"
    elif isinstance(payload, dict) and isinstance(payload.get("events"), list):
        records = payload["events"]
        source = payload.get("source", "json-batch")
    else:
        raise APIError(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "invalid_batch",
            "JSON batch must be an array or an object with an events array",
        )
    if not records:
        raise APIError(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "empty_batch",
            "events must not be empty",
        )
    if len(records) > settings.max_events_per_batch:
        raise APIError(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            "batch_too_large",
            "batch exceeds the configured record limit",
            {"max_records": settings.max_events_per_batch},
        )
    if not isinstance(source, str) or not source.strip():
        raise APIError(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "invalid_source",
            "source must be text",
        )
    return records, source.strip()[:100]


@app.get("/api/v1/health", response_model=HealthResponse)
def health(request: Request, response: Response) -> HealthResponse:
    database_ok = database_is_healthy()
    if not database_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthResponse(
        status="ok" if database_ok else "degraded",
        service="ok",
        database="ok" if database_ok else "unavailable",
        schema_revision=settings.schema_revision,
        request_id=request.state.request_id,
    )


@app.post("/api/v1/events/ingest")
async def ingest_events(request: Request) -> dict[str, Any]:
    idempotency_key = _require_idempotency_key(request)
    previous = repository.get_run_by_idempotency_key(idempotency_key)
    if previous is not None:
        return previous
    records, source = _batch_records(await _json_body(request))
    return repository.ingest(records, idempotency_key=idempotency_key, source=source)


@app.post("/api/v1/events/upload")
async def upload_events(request: Request) -> dict[str, Any]:
    idempotency_key = _require_idempotency_key(request)
    previous = repository.get_run_by_idempotency_key(idempotency_key)
    if previous is not None:
        return previous
    body = await request.body()
    if len(body) > settings.max_payload_bytes:
        raise APIError(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            "payload_too_large",
            "request payload exceeds the configured limit",
            {"max_bytes": settings.max_payload_bytes},
        )
    records: list[Any] = []
    for line in body.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as error:
            records.append(ParseFailure(f"invalid JSON at line {error.lineno}"))
    if not records:
        raise APIError(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "empty_upload",
            "JSONL upload is empty",
        )
    if len(records) > settings.max_events_per_batch:
        raise APIError(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            "batch_too_large",
            "upload exceeds the configured record limit",
            {"max_records": settings.max_events_per_batch},
        )
    return repository.ingest(records, idempotency_key=idempotency_key, source="jsonl-upload")


@app.get("/api/v1/ingestion-runs/{run_id}")
def get_ingestion_run(run_id: str) -> dict[str, Any]:
    run = repository.get_run(run_id)
    if run is None:
        raise APIError(
            status.HTTP_404_NOT_FOUND,
            "ingestion_run_not_found",
            "ingestion run was not found",
        )
    return run


@app.get("/api/v1/events")
def list_events(
    limit: int = 100,
    offset: int = 0,
    source_event_id: str | None = None,
    event_type: str | None = None,
) -> dict[str, Any]:
    if limit < 1 or limit > MAX_PAGE_SIZE or offset < 0:
        raise APIError(
            status.HTTP_400_BAD_REQUEST,
            "invalid_pagination",
            "limit must be between 1 and 100 and offset must be non-negative",
        )
    items, total = repository.list_events(
        limit=limit,
        offset=offset,
        source_event_id=source_event_id,
        event_type=event_type,
    )
    return {"items": items, "limit": limit, "offset": offset, "total": total}


@app.get("/api/v1/incidents")
def list_incidents(limit: int = 100, offset: int = 0) -> dict[str, Any]:
    if limit < 1 or limit > MAX_PAGE_SIZE or offset < 0:
        raise APIError(
            status.HTTP_400_BAD_REQUEST,
            "invalid_pagination",
            "limit must be between 1 and 100 and offset must be non-negative",
        )
    items, total = repository.list_incidents(limit=limit, offset=offset)
    return {
        "items": [repository._incident_response(item) for item in items],
        "limit": limit,
        "offset": offset,
        "total": total,
    }


@app.get("/api/v1/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict[str, Any]:
    incident = repository.get_incident(incident_id)
    if incident is None:
        raise APIError(status.HTTP_404_NOT_FOUND, "incident_not_found", "incident was not found")
    return incident


@app.get("/api/v1/incidents/{incident_id}/timeline")
def get_incident_timeline(incident_id: str) -> dict[str, Any]:
    timeline = repository.incident_timeline(incident_id)
    if timeline is None:
        raise APIError(status.HTTP_404_NOT_FOUND, "incident_not_found", "incident was not found")
    return {"incident_id": incident_id, "items": timeline}


@app.get("/api/v1/incidents/{incident_id}/findings")
def get_incident_findings(incident_id: str) -> dict[str, Any]:
    findings = repository.incident_findings(incident_id)
    if findings is None:
        raise APIError(status.HTTP_404_NOT_FOUND, "incident_not_found", "incident was not found")
    return {"incident_id": incident_id, "items": findings}


@app.post("/api/v1/incidents/{incident_id}/investigations")
def start_investigation(
    incident_id: str, payload: InvestigationRequest | None = None
) -> dict[str, Any]:
    provider = payload.provider if payload is not None else settings.ai_provider
    try:
        return investigations.start(incident_id, provider_name=provider)
    except InvestigationError as error:
        _raise_service_error(error)


@app.get("/api/v1/investigations/{run_id}")
def get_investigation(run_id: str) -> dict[str, Any]:
    result = investigations.get(run_id)
    if result is None:
        raise APIError(
            status.HTTP_404_NOT_FOUND, "investigation_not_found", "investigation was not found"
        )
    return result


@app.post("/api/v1/incidents/{incident_id}/response-plans")
def create_response_plan(incident_id: str, payload: ResponsePlanRequest) -> dict[str, Any]:
    try:
        return responses.propose(incident_id, payload)
    except ResponseError as error:
        _raise_service_error(error)


@app.get("/api/v1/response-actions/{action_id}")
def get_response_action(action_id: str) -> dict[str, Any]:
    result = responses.get_action(action_id)
    if result is None:
        raise APIError(
            status.HTTP_404_NOT_FOUND, "response_action_not_found", "response action was not found"
        )
    return result


@app.post("/api/v1/response-actions/{action_id}/approve")
def approve_response_action(action_id: str, payload: ActionDecisionRequest) -> dict[str, Any]:
    try:
        return responses.approve(action_id, payload)
    except ResponseError as error:
        _raise_service_error(error)


@app.post("/api/v1/response-actions/{action_id}/reject")
def reject_response_action(action_id: str, payload: ActionDecisionRequest) -> dict[str, Any]:
    try:
        return responses.reject(action_id, payload)
    except ResponseError as error:
        _raise_service_error(error)


@app.post("/api/v1/response-actions/{action_id}/execute")
def execute_response_action(
    action_id: str,
    request: Request,
    payload: ActionDecisionRequest,
) -> dict[str, Any]:
    idempotency_key = request.headers.get("idempotency-key", "")
    try:
        return responses.execute(action_id, payload, idempotency_key)
    except ResponseError as error:
        _raise_service_error(error)


@app.get("/api/v1/response-actions/{action_id}/verification")
def verify_response_action(action_id: str) -> dict[str, Any]:
    try:
        return responses.verify(action_id)
    except ResponseError as error:
        _raise_service_error(error)


@app.get("/api/v1/incidents/{incident_id}/audit")
def get_incident_audit(incident_id: str) -> dict[str, Any]:
    result = responses.get_audit(incident_id)
    if result is None:
        raise APIError(status.HTTP_404_NOT_FOUND, "incident_not_found", "incident was not found")
    return {"incident_id": incident_id, "items": result}
