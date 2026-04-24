# Pentest Recon Tool

Ferramenta local para automação de **recon inicial** e **análise de segurança**
em aplicações web. Roda em `localhost`, com **CLI** e **dashboard web**.
Saída pensada para **copy/paste em relatórios manuais** — sem PDFs,
sem JSON cru exposto ao usuário.

## Funcionalidades

| Scanner | O que faz |
| ------- | --------- |
| `headers` | Verifica HSTS, X-Frame-Options, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, banner disclosure |
| `tls` | Versão TLS, certificado, cifras fracas por protocolo |
| `ffuf` | Fuzzing de diretórios (wordlist customizável) → `[SITEMAP]` |
| `arjun` | Descoberta de parâmetros HTTP → `[PARAM DISCOVERY]` |
| `nuclei` | Templates ProjectDiscovery → `[NUCLEI][SEV]` |
| `nikto` | Scan clássico → `[NIKTO][SEV]` |
| `custom` | Métodos perigosos, CORS, open redirect, directory listing |

Todos os achados são normalizados internamente em `Finding`, com **score 0–100**
e status (OK / Atenção / Crítico / Risco extremo).

## Arquitetura

```
[L] Pentesting/
├── backend/
│   ├── main.py             FastAPI (rotas + serving do front)
│   ├── models.py           Pydantic — Finding, ScanResult, etc
│   ├── scanner_manager.py  Orquestra scanners em paralelo + scoring
│   ├── formatters.py       Render terminal/UI no formato exato pedido
│   ├── security.py         Sanitização de URL + bloqueio de alvos internos
│   └── scanners/
│       ├── headers.py
│       ├── tls.py
│       ├── ffuf.py
│       ├── arjun.py
│       ├── nuclei.py
│       ├── nikto.py
│       └── custom.py
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── wordlists/              ← coloque raft-large-directories.txt aqui
├── cli.py                  CLI runner
├── requirements.txt
└── Dockerfile              (opcional)
```

## Instalação local

### 1. Dependências Python

```bash
cd "[L] Pentesting"
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Ferramentas externas (cada uma é opcional — o scanner avisa caso falte)

**ffuf** (Go):
```bash
go install github.com/ffuf/ffuf/v2@latest
```

**nuclei** (Go):
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

**arjun** (Python):
```bash
pipx install arjun
# ou: pip install arjun
```

**nikto**:
```bash
# Debian/Ubuntu
sudo apt install nikto
# macOS
brew install nikto
```

### 3. Wordlist padrão

A ferramenta procura `wordlists/raft-large-directories.txt`. Para baixar:

```bash
mkdir -p wordlists
curl -L -o wordlists/raft-large-directories.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt
```

Se o arquivo não existir, o ffuf cai para uma wordlist mínima embutida (apenas
para ambientes de teste).

## Uso

### Modo web (dashboard)

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Abra `http://127.0.0.1:8000`, insira a URL alvo, escolha **Rápido** ou
**Completo**, opcionalmente envie uma wordlist customizada e clique
**Executar scan**. O dashboard exibe:

- Score colorido (OK / Atenção / Crítico / Risco extremo)
- Bloco terminal completo (botão **Copiar tudo**)
- Cada seção isolada com botão **Copiar** próprio

### Modo CLI

```bash
# scan rápido (headers + tls + custom)
python cli.py https://exemplo.com

# scan completo
python cli.py https://exemplo.com --full

# scan completo com wordlist específica
python cli.py https://exemplo.com --full --wordlist minha-lista.txt
```

A saída é exatamente:

```
===== SCAN RESULTS =====
Target: https://exemplo.com    Tipo: full
[HEADER] Strict-Transport-Security: max-age=31536000
[HEADER] Content-Security-Policy: AUSENTE
...
[TLS] Versão negociada: TLSv1.3
[TLS] Cifra negociada: TLS_AES_256_GCM_SHA384
O protocolo não utiliza cifras fracas
[SITEMAP]
/admin (403) /login (200) /api (301) /dashboard (200)
[PARAM DISCOVERY]
/api/login → user, password
/api/search → query, page
[VULNERABILITIES]
[NUCLEI][HIGH] Exposed Panel → /admin
[NUCLEI][MEDIUM] Missing Security Header → /
[NIKTO][INFO] X-Powered-By header exposed
[NIKTO][LOW] Allowed HTTP Methods: GET, POST, OPTIONS
[CUSTOM][HIGH] CORS misconfiguration → /api
[CUSTOM][MEDIUM] Directory listing enabled → /uploads
========================
Score: 72/100   Status: Atenção
```

Quando uma cifra fraca é detectada, o formato exato pedido é mantido:

```
Cifras fracas TLS 1.2: {TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA, ...}
```

### Modo Docker (opcional)

Imagem pré-empacotada com **ffuf, nuclei, arjun, nikto** já instalados:

```bash
docker build -t pentest-recon .
docker run --rm -p 8000:8000 pentest-recon
```

## Segurança

- URLs são sanitizadas: apenas `http`/`https`, sem credenciais embutidas.
- Resolução DNS é validada — qualquer hostname que aponte para
  `127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `::1` ou
  IPs reservados é **rejeitado**.
- Hostnames `localhost`, `*.local`, `*.internal`, `*.lan`,
  `metadata.google.internal` são bloqueados.
- Cada scanner tem **timeout duro** (3 min) e roda em subprocesso isolado.
- Wordlists customizadas têm o nome sanitizado (sem path traversal) e
  limite de 50 MB.

## API REST

| Método | Rota | Descrição |
|--------|------|-----------|
| `POST` | `/api/scan` | dispara scan (`{url, scan_type, wordlist?}`) → `{scan_id}` |
| `GET`  | `/api/scan/{scan_id}` | status + saída pronta + sections |
| `GET`  | `/api/scans` | lista scans em memória |
| `GET`  | `/api/wordlists` | lista wordlists disponíveis |
| `POST` | `/api/wordlists/upload` | upload de wordlist (`multipart/form-data`) |

A API **nunca devolve JSON cru de scanners** ao cliente. Ela devolve apenas
texto formatado pronto para copy/paste, mais campos curtos (`score`, `status`).

## Expansão

Para adicionar um novo scanner:

1. Crie `backend/scanners/<nome>.py` com a função
   `async def run_<nome>_scan(target: str, opts: dict) -> ScannerResult`.
2. Registre em `scanner_manager.py` (`_scanner_factory` + `SCANNERS_FULL`).
3. Acrescente formatador em `formatters.py` se a saída exigir formato próprio.

Não é preciso alterar o frontend — a section `vulnerabilities` agrega
findings de qualquer scanner com `source` em `("nuclei", "nikto", "custom")`.
Para uma section própria, expanda `_build_sections` em `backend/main.py` e
adicione a label correspondente em `frontend/app.js`.
