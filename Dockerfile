FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml ./
COPY src/ src/

RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

FROM python:3.12-slim

LABEL maintainer="Log Redaction Team"
LABEL description="日志脱敏 CLI 工具 - 容器化部署镜像"
LABEL org.opencontainers.image.source="https://github.com/example/log-redaction-cli"

RUN groupadd -r logredact && useradd -r -g logredact -d /home/logredact -s /sbin/nologin logredact

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/log-redact /usr/local/bin/log-redact

RUN mkdir -p /data/input /data/output /data/archive /data/keys && \
    chown -R logredact:logredact /data

WORKDIR /data

USER logredact

ENV LOG_REDACT_MAX_MEMORY_MB=512
ENV LOG_REDACT_MAX_INPUT_SIZE_MB=500

ENTRYPOINT ["log-redact"]
CMD ["--help"]
