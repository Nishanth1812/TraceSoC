import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, BrokenBarrierError, local
from uuid import uuid4

import pytest
import sqlalchemy as sa

from apps.api.app.database import initialize_schema
from apps.api.app.repository import EvidenceRepository
from apps.api.app.response_service import ResponseError, ResponseService
from apps.api.app.schema import incidents
from apps.api.app.schemas.response import ActionDecisionRequest, ResponsePlanRequest
from apps.api.tests.test_investigation_response import action_payload, primary_events


def check_concurrent_decisions(engine):
    initialize_schema(engine)
    EvidenceRepository(engine).ingest(primary_events(), idempotency_key="primary", source="test")
    service = ResponseService(engine)
    action = service.propose("INC-PRIMARY-001", ResponsePlanRequest(**action_payload()))
    barrier = Barrier(2)
    state = local()
    original = service._action

    def synchronize(connection, action_id, **kwargs):
        result = original(connection, action_id, **kwargs)
        if not getattr(state, "waited", False):
            state.waited = True
            try:
                barrier.wait(timeout=2)
            except BrokenBarrierError:
                pass
        return result

    service._action = synchronize

    def decide(approve):
        try:
            method = service.approve if approve else service.reject
            return method(action["action_id"], ActionDecisionRequest())["status"]
        except ResponseError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(decide, [True, False]))
    assert "action_not_pending" in results
    assert len(set(results) & {"approved", "rejected"}) == 1


def test_sqlite_concurrent_decisions(tmp_path):
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'concurrency.db'}")
    try:
        check_concurrent_decisions(engine)
    finally:
        engine.dispose()


@pytest.mark.skipif(not os.getenv("TEST_POSTGRES_URL"), reason="requires TEST_POSTGRES_URL")
def test_postgres_concurrent_decisions():
    admin = sa.create_engine(os.environ["TEST_POSTGRES_URL"])
    schema = f"tracesoc_test_{uuid4().hex}"
    with admin.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    engine = sa.create_engine(os.environ["TEST_POSTGRES_URL"], connect_args={"options": f"-csearch_path={schema}"})
    try:
        check_concurrent_decisions(engine)
        with engine.begin() as connection:
            connection.execute(sa.update(incidents).values(status="investigating"))
        service = ResponseService(engine)
        payload = ResponsePlanRequest(**action_payload())
        actions = [service.propose("INC-PRIMARY-001", payload) for _ in range(2)]
        for action in actions:
            service.approve(action["action_id"], ActionDecisionRequest())

        barrier = Barrier(2)
        original = service._simulated_session

        def synchronize_session(connection, session_id):
            result = original(connection, session_id)
            barrier.wait(timeout=5)
            return result

        service._simulated_session = synchronize_session

        def execute(action):
            try:
                return service.execute(action["action_id"], ActionDecisionRequest(), "same-key")["status"]
            except ResponseError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(execute, actions))
        assert sorted(results) == ["idempotency_key_reused", "succeeded"]
    finally:
        engine.dispose()
        with admin.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
        admin.dispose()
