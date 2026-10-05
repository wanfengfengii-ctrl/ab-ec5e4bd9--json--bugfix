# 遥测网关镜像：纯标准库实现，无需联网安装依赖
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY app ./app
COPY verify ./verify
COPY tests ./tests
COPY keys ./keys

# 构建期语法门禁：任何编译错误都会让镜像构建失败
RUN python -m compileall -q /app/app /app/verify /app/tests \
    && useradd --system --uid 10001 appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /data

USER appuser

ENV HOST=0.0.0.0 \
    PORT=8000 \
    KEYS_FILE=/app/keys/keys.json \
    DATA_DIR=/data \
    SKEW_SECONDS=300

EXPOSE 8000

CMD ["python", "-m", "app.server"]
