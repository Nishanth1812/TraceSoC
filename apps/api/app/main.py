from uuid import uuid4

from fastapi import FastAPI, Request, Response, status

from .config import get_settings
from .database import database_is_healthy
from .schemas.health import HealthResponse

settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0")


@app.middleware("http")
async def request_id_middleware(request: Request, call_next) -> Response:
    request_id = request.headers.get("x-request-id") or str(uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["x-request-id"] = request_id
    return response


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
