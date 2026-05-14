FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir .[all]

COPY agentwall ./agentwall
COPY policies ./policies
COPY demo ./demo

EXPOSE 8000 8501

COPY scripts/start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
