FROM python:3.11-slim

WORKDIR /app

# Install system deps for psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc && \
    rm -rf /var/lib/apt/lists/*

# Copy and install Python deps in two stages (heavy ML first, rest after)
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=300 -r requirements.txt && \
    rm -rf /tmp/*

# Copy application code
COPY ./backend ./backend
COPY ./ai_engine ./ai_engine
COPY ./blockchain_audit ./blockchain_audit

ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
