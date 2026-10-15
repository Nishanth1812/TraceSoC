from typing import Literal

from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "degraded"]
    service: Literal["ok"]
    database: Literal["ok", "unavailable"]
    schema_revision: str
    request_id: str
