# aurora-hack-labs

Reproducible, intentionally vulnerable Docker labs for the
[aurora-hack.dev](https://www.aurora-hack.dev/) case studies.

These labs do **not** run a local LLM. They model the vulnerable tool and
backend boundary so students can focus on the security behavior with a normal
browser or `curl`.

## Requirements

- Docker Desktop with Compose
- 2 GB of free memory
- `curl` or a browser

## Labs

| Lab | Start command | Local URL |
| --- | --- | --- |
| Arbitrary file read via ZIP links | `docker compose -f labs/arbitrary-file-read/docker-compose.yml up --build` | http://localhost:8081 |
| RCE via remote pickle loading | `docker compose -f labs/rce-pickle/docker-compose.yml up --build` | http://localhost:8082 |
| RAG SQL injection with debug leakage | `docker compose -f labs/rag-sqli/docker-compose.yml up --build` | http://localhost:8083 |

Each lab has its own README with the vulnerable request, expected result and
the defensive lesson. Stop a lab with `Ctrl+C` and remove containers with:

```bash
docker compose -f labs/<lab>/docker-compose.yml down
```

## Safety

Run these labs only on a local machine or an isolated training network. They
contain intentionally vulnerable code and fake data. Do not expose the
services to the public internet, add real credentials, or point them at
production systems.
