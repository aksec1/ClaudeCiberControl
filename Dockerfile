FROM python:3.11-slim

LABEL maintainer="ClaudeCiberControl Security Team"
LABEL description="Security Scanner Suite - MITRE ATT&CK | NIST | CIS Controls v8"

# System deps: nmap + build tools
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install python-nmap (may need manual copy on some platforms)
RUN pip install --no-cache-dir python-nmap || \
    (pip download python-nmap -d /tmp/nmap_pkg && \
     cd /tmp && tar xzf /tmp/nmap_pkg/python-nmap-*.tar.gz && \
     cp -r /tmp/python-nmap-*/nmap /usr/local/lib/python3.11/dist-packages/)

# Copy application code
COPY . .

# Output directory (override with volume mount)
RUN mkdir -p output/reports output/logs

# Non-root user for security
RUN useradd -m -u 1000 scanner && chown -R scanner:scanner /app
USER scanner

ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
