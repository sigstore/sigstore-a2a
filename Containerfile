FROM python:3.13-slim AS base

WORKDIR /app

RUN pip install --no-cache-dir uv hatch

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY sigstore_a2a/ ./sigstore_a2a/

RUN hatch build && pip install --no-cache-dir dist/*.whl

ENTRYPOINT ["sigstore-a2a"]

