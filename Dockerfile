# Security Tools Platform - Docker Configuration
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directory
RUN mkdir -p data/samples data/logs

# Set environment variables
ENV PYTHONPATH=/app
ENV ENVIRONMENT=production
ENV DATABASE_PATH=data/security_tools.db

# Expose ports
EXPOSE 8000 8050

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Create non-root user for security
RUN useradd -m -u 1000 securitytools && \
    chown -R securitytools:securitytools /app
USER securitytools

# Start command
CMD ["python", "main.py"]
