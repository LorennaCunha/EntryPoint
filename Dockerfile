# Imagem com todas as ferramentas externas pré-instaladas.
# Build:  docker build -t pentest-recon .
# Run:    docker run --rm -p 8000:8000 pentest-recon
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# --- ferramentas de sistema + nikto + go (para nuclei/ffuf) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git nikto perl libnet-ssleay-perl libwhisker2-perl \
        golang pipx \
    && rm -rf /var/lib/apt/lists/*

# --- ferramentas Go (ffuf + nuclei) ---
ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin
RUN go install github.com/ffuf/ffuf/v2@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# --- arjun (descoberta de parâmetros) ---
RUN pipx ensurepath && pipx install arjun
ENV PATH=$PATH:/root/.local/bin

# --- nuclei templates ---
RUN nuclei -update-templates -silent || true

# --- seclists (para wordlist padrão) ---
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists \
    || true

# --- app ---
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY wordlists/ ./wordlists/
COPY cli.py ./

EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
