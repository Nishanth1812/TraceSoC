FROM python:3.11-slim

WORKDIR /workspace

COPY pyproject.toml uv.lock README.md ./
RUN pip install --no-cache-dir uv \
    && uv sync --no-dev --no-install-project

COPY apps ./apps
COPY scripts ./scripts
COPY data ./data

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "apps.api.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
