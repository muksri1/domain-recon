# Domain Recon — containerized dashboard.
# Build:  docker build -t domain-recon .
# Run:    docker run --rm -p 5000:5000 domain-recon   (open http://localhost:5000)
FROM python:3.12-slim

# Don't buffer stdout/stderr; no .pyc files.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application.
COPY reconlib/ ./reconlib/
COPY templates/ ./templates/
COPY static/ ./static/
COPY app.py cli.py ./

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 5000

# Bind to 0.0.0.0 so the dashboard is reachable from outside the container.
CMD ["python", "app.py", "--host", "0.0.0.0", "--port", "5000"]
