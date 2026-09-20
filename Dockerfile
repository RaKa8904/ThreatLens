# ============================================================================
# Stage 1: Build React SOC Dashboard Frontend
# ============================================================================
FROM node:20-alpine AS frontend-builder
WORKDIR /frontend-build

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ============================================================================
# Stage 2: Production Multi-Process Container (Zeek + Redis + FastAPI + Nginx)
# ============================================================================
FROM zeek/zeek:latest AS runtime

# Prevent interactive prompts during apt installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system utilities, Python 3, Redis, Nginx, and Supervisor
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    redis-server \
    nginx \
    supervisor \
    tcpreplay \
    inotify-tools \
    procps \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python backend dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip3 install --no-cache-dir -r /app/backend/requirements.txt

# Copy application source code
COPY backend /app/backend
COPY engine /app/engine
COPY ingest /app/ingest
COPY config /app/config
COPY Favicon.svg /app/Favicon.svg

# Copy compiled frontend from Stage 1
COPY --from=frontend-builder /frontend-build/dist /app/frontend/dist

# Configure Nginx reverse proxy (listening on Hugging Face exposed port 7860)
RUN rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf
COPY config/nginx.conf /etc/nginx/conf.d/default.conf

# Setup runtime log and PCAP drop directories
RUN mkdir -p /logs /pcaps /data/redis /var/log /var/run

# Hugging Face Spaces exposes port 7860
EXPOSE 7860

# Launch supervisord to manage Redis, FastAPI backend, and Nginx ingress
CMD ["supervisord", "-c", "/app/config/supervisord.conf"]
