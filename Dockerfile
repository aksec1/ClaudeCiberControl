FROM python:3.11-slim

LABEL maintainer="ClaudeCiberControl Security Team"
LABEL description="Security Scanner Suite - MITRE ATT&CK | NIST | CIS Controls v8"

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN pip install --no-cache-dir python-nmap || \
    (pip download python-nmap -d /tmp/nmap_pkg && \
     cd /tmp && tar xzf /tmp/nmap_pkg/python-nmap-*.tar.gz && \
     cp -r /tmp/python-nmap-*/nmap /usr/local/lib/python3.11/dist-packages/)

COPY . .

RUN mkdir -p output/reports output/logs

RUN useradd -m -u 1000 scanner && chown -R scanner:scanner /app
USER scanner

ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
