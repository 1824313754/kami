FROM node:22-slim AS frontend

WORKDIR /frontend
COPY frontend-admin/package*.json ./
RUN npm ci
COPY frontend-admin/ ./
RUN npm run build

FROM python:3.12-slim

ARG SOURCE_REPOSITORY=https://github.com/1824313754/kami
LABEL org.opencontainers.image.source=$SOURCE_REPOSITORY

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYFAKA_HOST=0.0.0.0 \
    PYFAKA_PORT=8099 \
    PYFAKA_DEBUG=0 \
    PYFAKA_TIMEZONE=Asia/Shanghai \
    TZ=Asia/Shanghai

COPY requirements-python.txt .
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates nodejs \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements-python.txt

COPY run.py .
COPY pyfaka_app ./pyfaka_app
COPY --from=frontend /frontend/dist/ ./pyfaka_app/static/app/

EXPOSE 8099

CMD ["python", "run.py"]
