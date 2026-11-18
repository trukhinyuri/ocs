FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
WORKDIR /src
COPY go.mod .
COPY reference/go ./reference/go
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/ocs-go ./reference/go

FROM python:3.13.15-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b
WORKDIR /app
COPY uv.lock go.mod LICENSE .dockerignore ./
COPY stand/kubernetes/requirements.py /tmp/requirements.py
RUN python /tmp/requirements.py > /tmp/requirements.txt && python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements.txt
COPY schemas ./schemas
COPY spec ./spec
COPY examples ./examples
COPY reference ./reference
COPY stand/kubernetes ./stand/kubernetes
COPY assurance/provider/criteria.json ./assurance/provider/criteria.json
COPY LICENSE /usr/share/ocs/LICENSE
COPY --from=builder /out/ocs-go /usr/local/bin/ocs-go
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 65532:65532
ENTRYPOINT ["python", "-I", "/app/stand/kubernetes/gateway.py"]
