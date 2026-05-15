FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# ── Full install (dashboard / API demo) ──────────────────────────────────────
COPY pyproject.toml ./
RUN pip install --no-cache-dir .[all]

COPY agentwall ./agentwall
COPY policies ./policies
COPY demo ./demo

EXPOSE 8000 8501

COPY scripts/start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]

# ── Live-demo target  (build with: docker build --target livedemo) ────────────
FROM python:3.11-slim AS livedemo

ENV PYTHONUNBUFFERED=1 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /app

COPY agentwall ./agentwall
COPY live_demo ./live_demo
COPY pyproject.toml .streamlit ./

# Slim deps — no Azure SDK needed, rule engine works offline
RUN pip install --no-cache-dir \
        streamlit>=1.32 \
        pydantic>=2.6 \
        pyyaml>=6.0 \
        rapidfuzz>=3.6 \
        regex>=2024.0 \
        structlog>=24.1 \
        aiosqlite>=0.20 \
        openai>=1.0 \
        anthropic>=0.25 && \
    pip install --no-cache-dir -e . --no-deps

EXPOSE 8501
CMD ["python", "-m", "streamlit", "run", "live_demo/app.py"]
